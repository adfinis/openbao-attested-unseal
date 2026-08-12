package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
	adminOperationNodeEvidenceChallenge = "NODE_EVIDENCE_CHALLENGE"
	adminOperationEvidenceCheck         = "EVIDENCE_CHECK"
	adminOperationNodeEvidenceList      = "NODE_EVIDENCE_LIST"
	adminOperationNodeEvidencePublish   = "NODE_EVIDENCE_PUBLISH"
)

type adminAuditStore interface {
	InsertAuditEvent(ctx context.Context, event AuditEvent) error
}

type nodeEvidenceChallengeStore interface {
	CreateChallenge(ctx context.Context, challenge Challenge) error
	ChallengeNonce(
		ctx context.Context,
		challengeID string,
		clusterID string,
		subject string,
		operation protocolv1.Operation,
		now time.Time,
	) ([]byte, error)
	ConsumeChallenge(
		ctx context.Context,
		challengeID string,
		clusterID string,
		subject string,
		operation protocolv1.Operation,
		now time.Time,
	) error
}

// AdminService implements broker-local administrative APIs.
type AdminService struct {
	protocolv1.UnimplementedAdminServiceServer
	nodeEvidence                 NodeEvidenceStore
	auditStore                   adminAuditStore
	audit                        *FileAuditSink
	store                        Store
	challengeStore               nodeEvidenceChallengeStore
	verifier                     EvidenceVerifier
	challengeTTL                 time.Duration
	nodeEvidenceTTL              time.Duration
	nodeEvidenceRetention        time.Duration
	clusterID                    string
	policyID                     string
	allowFakeNodeEvidencePublish bool
	nodeEvidencePublishProviders []string
	nodeEvidenceTPMPolicies      map[string]TPMNodeEvidencePolicy
	nodeEvidencePublishers       map[string]NodeEvidencePublisher
	clock                        func() time.Time
}

type adminServiceConfig struct {
	nodeEvidence                 NodeEvidenceStore
	auditStore                   adminAuditStore
	audit                        *FileAuditSink
	store                        Store
	challengeStore               nodeEvidenceChallengeStore
	verifier                     EvidenceVerifier
	challengeTTL                 time.Duration
	nodeEvidenceTTL              time.Duration
	nodeEvidenceRetention        time.Duration
	clusterID                    string
	policyID                     string
	allowFakeNodeEvidencePublish bool
	nodeEvidencePublishProviders []string
	nodeEvidenceTPMPolicies      map[string]TPMNodeEvidencePolicy
	nodeEvidencePublishers       map[string]NodeEvidencePublisher
}

// NewAdminService creates the broker admin service.
func NewAdminService(
	nodeEvidence NodeEvidenceStore,
	policyID string,
	allowFakeNodeEvidencePublish bool,
) AdminService {
	return newAdminService(adminServiceConfig{
		nodeEvidence:                 nodeEvidence,
		challengeStore:               NewMemoryChallengeStore(),
		policyID:                     policyID,
		allowFakeNodeEvidencePublish: allowFakeNodeEvidencePublish,
		challengeTTL:                 DefaultChallengeTTL,
		nodeEvidenceTTL:              DefaultKubernetesNodeEvidenceTTL,
		nodeEvidenceRetention:        DefaultKubernetesNodeEvidenceRetention,
	})
}

func newAdminService(config adminServiceConfig) AdminService {
	challengeStore := config.challengeStore
	if challengeStore == nil {
		challengeStore = NewMemoryChallengeStore()
	}
	return AdminService{
		nodeEvidence:                 config.nodeEvidence,
		auditStore:                   config.auditStore,
		audit:                        config.audit,
		store:                        config.store,
		challengeStore:               challengeStore,
		verifier:                     config.verifier,
		challengeTTL:                 config.challengeTTL,
		nodeEvidenceTTL:              config.nodeEvidenceTTL,
		nodeEvidenceRetention:        config.nodeEvidenceRetention,
		clusterID:                    strings.TrimSpace(config.clusterID),
		policyID:                     config.policyID,
		allowFakeNodeEvidencePublish: config.allowFakeNodeEvidencePublish,
		nodeEvidencePublishProviders: slices.Clone(config.nodeEvidencePublishProviders),
		nodeEvidenceTPMPolicies:      cloneTPMNodeEvidencePolicies(config.nodeEvidenceTPMPolicies),
		nodeEvidencePublishers:       cloneNodeEvidencePublishers(config.nodeEvidencePublishers),
		clock:                        time.Now,
	}
}

// Status reports which admin APIs are available.
func (s AdminService) Status(context.Context, *protocolv1.AdminStatusRequest) (*protocolv1.AdminStatusResponse, error) {
	if s.nodeEvidence == nil {
		return &protocolv1.AdminStatusResponse{
			Implemented: false,
			Message:     "admin node evidence APIs require Kubernetes node evidence storage",
		}, nil
	}
	return &protocolv1.AdminStatusResponse{
		Implemented: true,
		Message:     "admin node evidence APIs are available",
	}, nil
}

// ChallengeNodeEvidence creates a single-use challenge for one node evidence submission.
func (s AdminService) ChallengeNodeEvidence(
	ctx context.Context,
	req *protocolv1.NodeEvidenceChallengeRequest,
) (*protocolv1.NodeEvidenceChallengeResponse, error) {
	request, err := nodeEvidenceChallengeRequestFromProto(req)
	if err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error())
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
		return &protocolv1.NodeEvidenceChallengeResponse{Decision: decision.Proto()}, nil
	}
	if !s.acceptsNodeEvidenceCluster(request.ClusterID) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"node evidence cluster is not configured",
		)
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
		return &protocolv1.NodeEvidenceChallengeResponse{Decision: decision.Proto()}, nil
	}
	if !s.canPublishNodeEvidenceProvider(request.Provider) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			fmt.Sprintf("node evidence publish provider %q is not enabled", request.Provider),
		)
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
		return &protocolv1.NodeEvidenceChallengeResponse{Decision: decision.Proto()}, nil
	}
	if err := s.validateNodeEvidenceIdentity(request.NodeName, request.NodeUID, request.Provider); err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, err.Error())
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
		return &protocolv1.NodeEvidenceChallengeResponse{Decision: decision.Proto()}, nil
	}
	publisherID, code, err := s.authorizeNodeEvidencePublisher(ctx, request.NodeName, request.Provider)
	if err != nil {
		decision := Deny(s.policyID, code, err.Error())
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
		return &protocolv1.NodeEvidenceChallengeResponse{Decision: decision.Proto()}, nil
	}
	challengeID, err := randomID("node_chal")
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	ttl := s.challengeTTL
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	expiresAt := now.Add(ttl)
	challenge := Challenge{
		ID:        challengeID,
		Nonce:     nonce,
		ClusterID: request.ClusterID,
		Subject:   nodeEvidenceChallengeSubject(request, publisherID),
		Operation: protocolv1.Operation_OPERATION_ENROLL,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.challengeStore.CreateChallenge(ctx, challenge); err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence challenge failed")
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
		return &protocolv1.NodeEvidenceChallengeResponse{Decision: decision.Proto()}, nil
	}
	decision := Allow(s.policyID)
	s.auditNodeEvidence(ctx, adminOperationNodeEvidenceChallenge, request.ClusterID, request.NodeName, "", decision)
	return &protocolv1.NodeEvidenceChallengeResponse{
		ChallengeId:        challengeID,
		Nonce:              nonce,
		ExpiresUnixSeconds: expiresAt.Unix(),
		Decision:           decision.Proto(),
	}, nil
}

// PublishNodeEvidence verifies an untrusted submission and stores its safe projection.
func (s AdminService) PublishNodeEvidence(
	ctx context.Context,
	req *protocolv1.NodeEvidencePublishRequest,
) (*protocolv1.NodeEvidencePublishResponse, error) {
	if s.nodeEvidence == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
			"node evidence storage is not configured",
		)
		s.auditNodeEvidence(ctx, adminOperationNodeEvidencePublish, "", "", "", decision)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
	submission, err := nodeEvidenceSubmissionFromProto(req)
	if err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error())
		s.auditNodeEvidence(ctx, adminOperationNodeEvidencePublish, submission.ClusterID, submission.NodeName, "", decision)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	payloadHash := nodeEvidencePayloadHash(submission.Payload)
	if !s.acceptsNodeEvidenceCluster(submission.ClusterID) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"node evidence cluster is not configured",
		)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	if !s.canPublishNodeEvidenceProvider(submission.Provider) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			fmt.Sprintf("node evidence publish provider %q is not enabled", submission.Provider),
		)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	if err := s.validateNodeEvidenceIdentity(
		submission.NodeName,
		submission.NodeUID,
		submission.Provider,
	); err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, err.Error())
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	publisherID, code, err := s.authorizeNodeEvidencePublisher(ctx, submission.NodeName, submission.Provider)
	if err != nil {
		decision := Deny(s.policyID, code, err.Error())
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	subject := nodeEvidenceChallengeSubject(nodeevidence.ChallengeRequest{
		ClusterID: submission.ClusterID,
		NodeName:  submission.NodeName,
		NodeUID:   submission.NodeUID,
		Provider:  submission.Provider,
	}, publisherID)
	now := s.now().UTC()
	nonce, err := s.challengeStore.ChallengeNonce(
		ctx,
		submission.ChallengeID,
		submission.ClusterID,
		subject,
		protocolv1.Operation_OPERATION_ENROLL,
		now,
	)
	if err != nil {
		decision := nodeEvidenceChallengeDeny(s.policyID, err)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	evidence, err := verifyNodeEvidenceSubmission(submission, nonce, s.nodeEvidenceTPMPolicies)
	if err != nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
			"node evidence verification failed",
		)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	if err := s.challengeStore.ConsumeChallenge(
		ctx,
		submission.ChallengeID,
		submission.ClusterID,
		subject,
		protocolv1.Operation_OPERATION_ENROLL,
		now,
	); err != nil {
		decision := nodeEvidenceChallengeDeny(s.policyID, err)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			submission.ClusterID,
			submission.NodeName,
			payloadHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{Decision: decision.Proto()}, nil
	}
	evidence.CollectedAt = now
	evidence.ExpiresAt = now.Add(s.acceptedNodeEvidenceTTL(submission.RequestedTTL))
	if err := s.pruneNodeEvidence(ctx, evidence.ClusterID); err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence cleanup failed")
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			evidence.ClusterID,
			evidence.NodeName,
			evidence.EvidenceHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
	if err := s.nodeEvidence.PutNodeEvidence(ctx, evidence); err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error())
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			evidence.ClusterID,
			evidence.NodeName,
			evidence.EvidenceHash,
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
	decision := Allow(s.policyID)
	s.auditNodeEvidence(
		ctx,
		adminOperationNodeEvidencePublish,
		evidence.ClusterID,
		evidence.NodeName,
		evidence.EvidenceHash,
		decision,
	)
	return &protocolv1.NodeEvidencePublishResponse{
		Evidence: nodeEvidenceToProto(evidence, s.now()),
		Decision: decision.Proto(),
	}, nil
}

// ListNodeEvidence returns stored node evidence records for diagnostics.
func (s AdminService) ListNodeEvidence(
	ctx context.Context,
	req *protocolv1.NodeEvidenceListRequest,
) (*protocolv1.NodeEvidenceListResponse, error) {
	if s.nodeEvidence == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
			"node evidence storage is not configured",
		)
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceList, "", "", "", decision)
		return &protocolv1.NodeEvidenceListResponse{
			Decision: decision.Proto(),
		}, nil
	}
	if req == nil || req.GetClusterId() == "" {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, "cluster_id is required")
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceList, "", "", "", decision)
		return &protocolv1.NodeEvidenceListResponse{
			Decision: decision.Proto(),
		}, nil
	}
	if err := s.pruneNodeEvidence(ctx, req.GetClusterId()); err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence cleanup failed")
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceList, req.GetClusterId(), req.GetNodeName(), "", decision)
		return &protocolv1.NodeEvidenceListResponse{
			Decision: decision.Proto(),
		}, nil
	}
	records, err := s.nodeEvidence.ListNodeEvidence(ctx, req.GetClusterId(), req.GetNodeName())
	if err != nil {
		if errors.Is(err, ErrNodeEvidenceNotFound) {
			decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED, "node evidence is missing")
			s.auditNodeEvidence(ctx, adminOperationNodeEvidenceList, req.GetClusterId(), req.GetNodeName(), "", decision)
			return &protocolv1.NodeEvidenceListResponse{
				Decision: decision.Proto(),
			}, nil
		}
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence lookup failed")
		s.auditNodeEvidence(ctx, adminOperationNodeEvidenceList, req.GetClusterId(), req.GetNodeName(), "", decision)
		return &protocolv1.NodeEvidenceListResponse{
			Decision: decision.Proto(),
		}, nil
	}
	out := make([]*protocolv1.NodeEvidenceRecord, 0, len(records))
	now := s.now()
	for _, evidence := range records {
		out = append(out, nodeEvidenceToProto(evidence, now))
	}
	decision := Allow(s.policyID)
	s.auditNodeEvidence(ctx, adminOperationNodeEvidenceList, req.GetClusterId(), req.GetNodeName(), "", decision)
	return &protocolv1.NodeEvidenceListResponse{
		Evidence: out,
		Decision: decision.Proto(),
	}, nil
}

// CheckEvidence evaluates attestation evidence for diagnostics without consuming
// a challenge or using key material.
func (s AdminService) CheckEvidence(
	ctx context.Context,
	req *protocolv1.EvidenceCheckRequest,
) (*protocolv1.EvidenceCheckResponse, error) {
	if req == nil || strings.TrimSpace(req.GetClusterId()) == "" || req.GetEvidence() == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"cluster_id and evidence are required",
		)
		s.auditEvidenceCheck(ctx, "", "", reqEvidenceHash(req), decision)
		return &protocolv1.EvidenceCheckResponse{Decision: decision.Proto()}, nil
	}
	clusterID := strings.TrimSpace(req.GetClusterId())
	if s.store == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
			"policy store is not configured",
		)
		s.auditEvidenceCheck(ctx, clusterID, "", evidenceHash(req.GetEvidence()), decision)
		return &protocolv1.EvidenceCheckResponse{Decision: decision.Proto()}, nil
	}

	verifier := s.verifier
	if verifier == nil {
		verifier = DevelopmentEvidenceVerifier{}
	}
	verified, err := verifier.VerifyEvidence(ctx, req.GetEvidence())
	if err != nil {
		decision := evidenceCheckVerificationDeny(s.policyID, err)
		s.auditEvidenceCheck(ctx, clusterID, "", evidenceHash(req.GetEvidence()), decision)
		return &protocolv1.EvidenceCheckResponse{Decision: decision.Proto()}, nil
	}

	operation := req.GetOperation()
	if operation == protocolv1.Operation_OPERATION_UNSPECIFIED {
		operation = protocolv1.Operation_OPERATION_WRAP
	}
	engine := NewPolicyEngine(s.store, s.policyID, nil)
	engine.nodeEvidence = s.nodeEvidence
	engine.clock = s.now
	decision := engine.evaluateSubjectAndNodeEvidence(ctx, policyRequest{
		ClusterID: clusterID,
		Subject:   verified.Subject,
		Workload:  verified.Workload,
		Operation: operation,
	})
	nodeEvidence := s.diagnosticNodeEvidence(ctx, clusterID, verified.Workload.NodeName)
	s.auditEvidenceCheck(
		ctx,
		clusterID,
		verified.Workload.NodeName,
		evidenceHash(req.GetEvidence()),
		decision,
	)
	return &protocolv1.EvidenceCheckResponse{
		Decision:     decision.Proto(),
		Subject:      verified.Subject,
		Workload:     workloadIdentityToProto(verified.Workload),
		NodeEvidence: nodeEvidence,
	}, nil
}

func (s AdminService) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock()
}

func (s AdminService) pruneNodeEvidence(ctx context.Context, clusterID string) error {
	if s.nodeEvidence == nil {
		return nil
	}
	retention := s.nodeEvidenceRetention
	if retention <= 0 {
		retention = DefaultKubernetesNodeEvidenceRetention
	}
	_, err := s.nodeEvidence.PruneNodeEvidence(ctx, clusterID, s.now().UTC().Add(-retention))
	return err
}

func (s AdminService) diagnosticNodeEvidence(
	ctx context.Context,
	clusterID string,
	nodeName string,
) *protocolv1.NodeEvidenceRecord {
	if s.nodeEvidence == nil || strings.TrimSpace(nodeName) == "" {
		return nil
	}
	evidence, err := s.nodeEvidence.NodeEvidence(ctx, clusterID, nodeName)
	if err != nil {
		return nil
	}
	return nodeEvidenceToProto(evidence, s.now())
}

func (s AdminService) auditEvidenceCheck(
	ctx context.Context,
	clusterID string,
	nodeName string,
	hash string,
	decision PolicyDecision,
) {
	s.auditNodeEvidence(ctx, adminOperationEvidenceCheck, clusterID, nodeName, hash, decision)
}

func (s AdminService) auditNodeEvidence(
	ctx context.Context,
	operation string,
	clusterID string,
	nodeName string,
	evidenceHash string,
	decision PolicyDecision,
) {
	if s.auditStore == nil && (s.audit == nil || s.audit.path == "") {
		return
	}
	event, err := s.newNodeEvidenceAuditEvent(ctx, operation, clusterID, nodeName, evidenceHash, decision)
	if err != nil {
		return
	}
	if s.auditStore != nil {
		_ = s.auditStore.InsertAuditEvent(ctx, event)
	}
	if s.audit != nil && s.audit.path != "" {
		_ = s.audit.Write(ctx, event)
	}
}

func (s AdminService) newNodeEvidenceAuditEvent(
	ctx context.Context,
	operation string,
	clusterID string,
	nodeName string,
	evidenceHash string,
	decision PolicyDecision,
) (AuditEvent, error) {
	auditID, err := randomID("audit")
	if err != nil {
		return AuditEvent{}, err
	}
	return AuditEvent{
		SchemaVersion: 1,
		AuditID:       auditID,
		Time:          s.now().UTC().Format(time.RFC3339Nano),
		Subject:       nodeName,
		Operation:     operation,
		ClusterID:     clusterID,
		Decision:      decision.State.String(),
		PolicyID:      decision.PolicyID,
		Reason:        decision.Reason,
		EvidenceHash:  evidenceHash,
		RemoteAddress: remoteAddress(ctx),
		ErrorCode:     auditErrorCode(decision),
	}, nil
}

func evidenceCheckVerificationDeny(policyID string, err error) PolicyDecision {
	switch {
	case errors.Is(err, k8sprovider.ErrTokenReview):
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_BROKER_UNAVAILABLE, "kubernetes tokenreview failed")
	case errors.Is(err, k8sprovider.ErrUnauthenticated):
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, "kubernetes token is not authenticated")
	case errors.Is(err, k8sprovider.ErrInvalidEvidence):
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED, safeEvidenceCheckReason(err))
	default:
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED, "attestation verification failed")
	}
}

var safeEvidenceCheckReasons = []struct {
	fragment string
	reason   string
}{
	{"audience was not accepted", "kubernetes token audience was not accepted"},
	{"namespace is not allowed", "kubernetes namespace is not allowed"},
	{"service account is not allowed", "kubernetes service account is not allowed"},
	{"token is required", "kubernetes token is required"},
	{"pod-bound token claims are required", "pod-bound token claims are required"},
	{"pod-bound token node claim is required", "pod-bound token node claim is required"},
	{"pod name and UID claims are required", "pod name and UID claims are required"},
	{"pod lookup failed", "kubernetes pod lookup failed"},
	{"pod UID does not match token", "pod UID does not match token"},
	{"pod node does not match token", "pod node does not match token"},
	{"pod is not scheduled to a node", "pod is not scheduled to a node"},
	{"username is not a service account", "kubernetes username is not a service account"},
	{"service account username is incomplete", "kubernetes service account username is incomplete"},
	{"provider is not Kubernetes workload", "evidence provider is not Kubernetes workload"},
	{"unsupported evidence format", "unsupported Kubernetes evidence format"},
	{"payload is required", "evidence payload is required"},
	{"payload exceeds maximum size", "evidence payload exceeds maximum size"},
	{"decode payload", "evidence payload could not be decoded"},
}

func safeEvidenceCheckReason(err error) string {
	message := err.Error()
	for _, item := range safeEvidenceCheckReasons {
		if strings.Contains(message, item.fragment) {
			return item.reason
		}
	}
	return "attestation verification failed"
}

func reqEvidenceHash(req *protocolv1.EvidenceCheckRequest) string {
	if req == nil {
		return ""
	}
	return evidenceHash(req.GetEvidence())
}

func workloadIdentityToProto(workload WorkloadIdentity) *protocolv1.WorkloadIdentity {
	if workload == (WorkloadIdentity{}) {
		return nil
	}
	return &protocolv1.WorkloadIdentity{
		Namespace:      workload.Namespace,
		ServiceAccount: workload.ServiceAccount,
		PodName:        workload.PodName,
		PodUid:         workload.PodUID,
		NodeName:       workload.NodeName,
		NodeUid:        workload.NodeUID,
	}
}

func nodeEvidenceChallengeRequestFromProto(
	req *protocolv1.NodeEvidenceChallengeRequest,
) (nodeevidence.ChallengeRequest, error) {
	if req == nil {
		return nodeevidence.ChallengeRequest{}, errors.New("node evidence challenge request is required")
	}
	return nodeevidence.NormalizeChallengeRequest(nodeevidence.ChallengeRequest{
		ClusterID: req.GetClusterId(),
		NodeName:  req.GetNodeName(),
		NodeUID:   req.GetNodeUid(),
		Provider:  req.GetProviderId(),
	})
}

func nodeEvidenceSubmissionFromProto(
	req *protocolv1.NodeEvidencePublishRequest,
) (nodeevidence.Submission, error) {
	if req == nil || req.GetSubmission() == nil {
		return nodeevidence.Submission{}, errors.New("node evidence submission is required")
	}
	submission := req.GetSubmission()
	requestedTTLSeconds := submission.GetRequestedTtlSeconds()
	if requestedTTLSeconds <= 0 || requestedTTLSeconds > int64((365*24*time.Hour)/time.Second) {
		return nodeevidence.Submission{}, errors.New("requested_ttl_seconds is invalid")
	}
	return nodeevidence.NormalizeSubmission(nodeevidence.Submission{
		ClusterID:    submission.GetClusterId(),
		NodeName:     submission.GetNodeName(),
		NodeUID:      submission.GetNodeUid(),
		Provider:     submission.GetProviderId(),
		Format:       submission.GetFormat(),
		Payload:      submission.GetPayload(),
		ChallengeID:  submission.GetChallengeId(),
		RequestedTTL: time.Duration(requestedTTLSeconds) * time.Second,
	})
}

func nodeEvidenceChallengeSubject(request nodeevidence.ChallengeRequest, publisherID string) string {
	return "node-evidence:" + nodeEvidencePayloadHash([]byte(strings.Join([]string{
		request.ClusterID,
		request.NodeName,
		request.NodeUID,
		request.Provider,
		publisherID,
	}, "\x00")))
}

func nodeEvidenceChallengeDeny(policyID string, err error) PolicyDecision {
	switch {
	case errors.Is(err, ErrChallengeExpired):
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "node evidence challenge expired")
	case errors.Is(err, ErrChallengeReplayed):
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "node evidence challenge was replayed")
	case errors.Is(err, ErrChallengeNotFound), errors.Is(err, ErrChallengeMismatch):
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "node evidence challenge is invalid")
	default:
		return Deny(policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence challenge validation failed")
	}
}

func (s AdminService) validateNodeEvidenceIdentity(nodeName string, nodeUID string, provider string) error {
	if provider != nodeevidence.ProviderTPM2Quote {
		return nil
	}
	enrolled, ok := s.nodeEvidenceTPMPolicies[nodeName]
	if !ok || strings.TrimSpace(enrolled.NodeUID) != nodeUID {
		return errors.New("node TPM identity is not enrolled")
	}
	return nil
}

func (s AdminService) acceptedNodeEvidenceTTL(requested time.Duration) time.Duration {
	maximum := s.nodeEvidenceTTL
	if maximum <= 0 {
		maximum = DefaultKubernetesNodeEvidenceTTL
	}
	if requested > maximum {
		return maximum
	}
	return requested
}

func (s AdminService) acceptsNodeEvidenceCluster(clusterID string) bool {
	return s.clusterID == "" || s.clusterID == strings.TrimSpace(clusterID)
}

func (s AdminService) canPublishNodeEvidenceProvider(providerID string) bool {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return false
	}
	if providerID == NodeEvidenceProviderFakeLocal && s.allowFakeNodeEvidencePublish {
		return true
	}
	return slices.ContainsFunc(s.nodeEvidencePublishProviders, func(allowed string) bool {
		return strings.TrimSpace(allowed) == providerID
	})
}

// nodeEvidenceToProto returns the operator-safe diagnostic projection. It must
// not echo submitted raw claims, broker errors, policy payloads, or future
// evidence bodies.
func nodeEvidenceToProto(evidence NodeEvidence, now time.Time) *protocolv1.NodeEvidenceRecord {
	status := protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_FRESH
	if !evidence.ExpiresAt.After(now) {
		status = protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_STALE
	}
	return &protocolv1.NodeEvidenceRecord{
		ClusterId:            evidence.ClusterID,
		NodeName:             evidence.NodeName,
		NodeUid:              evidence.NodeUID,
		Provider:             protocolv1.AttestationProvider_ATTESTATION_PROVIDER_UNSPECIFIED,
		ProviderId:           evidence.Provider,
		EvidenceHash:         evidence.EvidenceHash,
		CollectedUnixSeconds: evidence.CollectedAt.Unix(),
		ExpiresUnixSeconds:   evidence.ExpiresAt.Unix(),
		Status:               status,
	}
}
