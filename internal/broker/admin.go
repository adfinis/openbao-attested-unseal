package broker

import (
	"context"
	"errors"
	"strings"
	"time"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
	adminOperationEvidenceCheck       = "EVIDENCE_CHECK"
	adminOperationNodeEvidenceList    = "NODE_EVIDENCE_LIST"
	adminOperationNodeEvidencePublish = "NODE_EVIDENCE_PUBLISH"
)

type adminAuditStore interface {
	InsertAuditEvent(ctx context.Context, event AuditEvent) error
}

// AdminService implements broker-local administrative APIs.
type AdminService struct {
	protocolv1.UnimplementedAdminServiceServer
	nodeEvidence                 NodeEvidenceStore
	auditStore                   adminAuditStore
	audit                        *FileAuditSink
	store                        Store
	verifier                     EvidenceVerifier
	nodeEvidenceRetention        time.Duration
	policyID                     string
	allowFakeNodeEvidencePublish bool
	clock                        func() time.Time
}

type adminServiceConfig struct {
	nodeEvidence                 NodeEvidenceStore
	auditStore                   adminAuditStore
	audit                        *FileAuditSink
	store                        Store
	verifier                     EvidenceVerifier
	nodeEvidenceRetention        time.Duration
	policyID                     string
	allowFakeNodeEvidencePublish bool
}

// NewAdminService creates the broker admin service.
func NewAdminService(
	nodeEvidence NodeEvidenceStore,
	policyID string,
	allowFakeNodeEvidencePublish bool,
) AdminService {
	return newAdminService(adminServiceConfig{
		nodeEvidence:                 nodeEvidence,
		policyID:                     policyID,
		allowFakeNodeEvidencePublish: allowFakeNodeEvidencePublish,
		nodeEvidenceRetention:        DefaultKubernetesNodeEvidenceRetention,
	})
}

func newAdminService(config adminServiceConfig) AdminService {
	return AdminService{
		nodeEvidence:                 config.nodeEvidence,
		auditStore:                   config.auditStore,
		audit:                        config.audit,
		store:                        config.store,
		verifier:                     config.verifier,
		nodeEvidenceRetention:        config.nodeEvidenceRetention,
		policyID:                     config.policyID,
		allowFakeNodeEvidencePublish: config.allowFakeNodeEvidencePublish,
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

// PublishNodeEvidence stores broker-trusted node evidence.
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
	if req == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"node evidence request is required",
		)
		s.auditNodeEvidence(ctx, adminOperationNodeEvidencePublish, "", "", "", decision)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
	if !s.allowFakeNodeEvidencePublish {
		record := req.GetEvidence()
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"fake node evidence publish is disabled",
		)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			record.GetClusterId(),
			record.GetNodeName(),
			record.GetEvidenceHash(),
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
	if providerID := nodeEvidenceProviderID(req.GetEvidence()); providerID != NodeEvidenceProviderFakeLocal {
		record := req.GetEvidence()
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"only fake-local node evidence can be published through this beta admin API",
		)
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			record.GetClusterId(),
			record.GetNodeName(),
			record.GetEvidenceHash(),
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
	evidence, err := nodeEvidenceFromProto(req.GetEvidence())
	if err != nil {
		record := req.GetEvidence()
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error())
		s.auditNodeEvidence(
			ctx,
			adminOperationNodeEvidencePublish,
			record.GetClusterId(),
			record.GetNodeName(),
			record.GetEvidenceHash(),
			decision,
		)
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: decision.Proto(),
		}, nil
	}
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

func nodeEvidenceFromProto(record *protocolv1.NodeEvidenceRecord) (NodeEvidence, error) {
	if record == nil {
		return NodeEvidence{}, errors.New("node evidence record is required")
	}
	if record.GetCollectedUnixSeconds() <= 0 || record.GetExpiresUnixSeconds() <= 0 {
		return NodeEvidence{}, errors.New("collected_unix_seconds and expires_unix_seconds are required")
	}
	collectedAt := time.Unix(record.GetCollectedUnixSeconds(), 0).UTC()
	expiresAt := time.Unix(record.GetExpiresUnixSeconds(), 0).UTC()
	return NodeEvidence{
		ClusterID:    record.GetClusterId(),
		NodeName:     record.GetNodeName(),
		NodeUID:      record.GetNodeUid(),
		Provider:     nodeEvidenceProviderID(record),
		EvidenceHash: record.GetEvidenceHash(),
		CollectedAt:  collectedAt,
		ExpiresAt:    expiresAt,
	}, nil
}

func nodeEvidenceProviderID(record *protocolv1.NodeEvidenceRecord) string {
	if record.GetProviderId() != "" {
		return record.GetProviderId()
	}
	if record.GetProvider() == protocolv1.AttestationProvider_ATTESTATION_PROVIDER_UNSPECIFIED {
		return ""
	}
	return record.GetProvider().String()
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
