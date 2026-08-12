package broker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

const (
	enrollmentOperationNodeEvidenceEnroll = "NODE_EVIDENCE_ENROLL"
	enrollmentOperationNodeEvidenceRevoke = "NODE_EVIDENCE_REVOKE"
	enrollmentOperationNodeEvidenceList   = "NODE_EVIDENCE_ENROLLMENT_LIST"
)

// EnrollmentService implements authenticated broker-owned enrollment lifecycles.
type EnrollmentService struct {
	protocolv1.UnimplementedEnrollmentServiceServer
	store      nodeevidence.EnrollmentRepository
	auditStore adminAuditStore
	audit      *FileAuditSink
	identities map[string]ControlPlaneIdentity
	clusterID  string
	policyID   string
	clock      func() time.Time
}

type enrollmentServiceConfig struct {
	store      nodeevidence.EnrollmentRepository
	auditStore adminAuditStore
	audit      *FileAuditSink
	identities map[string]ControlPlaneIdentity
	clusterID  string
	policyID   string
}

func newEnrollmentService(config enrollmentServiceConfig) EnrollmentService {
	return EnrollmentService{
		store:      config.store,
		auditStore: config.auditStore,
		audit:      config.audit,
		identities: cloneControlPlaneIdentities(config.identities),
		clusterID:  strings.TrimSpace(config.clusterID),
		policyID:   strings.TrimSpace(config.policyID),
		clock:      time.Now,
	}
}

// Status reports whether broker-owned enrollment storage is available.
func (s EnrollmentService) Status(
	context.Context,
	*protocolv1.EnrollmentStatusRequest,
) (*protocolv1.EnrollmentStatusResponse, error) {
	if s.store == nil {
		return &protocolv1.EnrollmentStatusResponse{
			Implemented: false,
			Message:     "node evidence enrollment storage is unavailable",
		}, nil
	}
	return &protocolv1.EnrollmentStatusResponse{
		Implemented: true,
		Message:     "authenticated node evidence enrollment is available",
	}, nil
}

// EnrollNodeEvidence creates or replaces one revisioned node trust policy.
func (s EnrollmentService) EnrollNodeEvidence(
	ctx context.Context,
	req *protocolv1.NodeEvidenceEnrollmentRequest,
) (*protocolv1.NodeEvidenceEnrollmentResponse, error) {
	request, reason, err := nodeEvidenceEnrollmentRequestFromProto(req, s.now())
	if err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error())
		_ = s.auditEnrollmentDecision(ctx, enrollmentOperationNodeEvidenceEnroll, "", "", "", reqAudit(req), decision)
		return &protocolv1.NodeEvidenceEnrollmentResponse{Decision: decision.Proto()}, nil
	}
	actor, code, err := s.authorize(ctx, request.ClusterID)
	if err != nil {
		decision := Deny(s.policyID, code, err.Error())
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceEnroll,
			actor,
			request.ClusterID,
			request.NodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentResponse{Decision: decision.Proto()}, nil
	}
	if !s.acceptsCluster(request.ClusterID) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"node evidence cluster is not configured",
		)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceEnroll,
			actor,
			request.ClusterID,
			request.NodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentResponse{Decision: decision.Proto()}, nil
	}
	if s.store == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
			"node evidence enrollment storage is unavailable",
		)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceEnroll,
			actor,
			request.ClusterID,
			request.NodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentResponse{Decision: decision.Proto()}, nil
	}
	decision := Allow(s.policyID)
	if err := s.auditEnrollmentDecision(
		ctx,
		enrollmentOperationNodeEvidenceEnroll,
		actor,
		request.ClusterID,
		request.NodeName,
		req.GetAudit(),
		decisionWithReason(decision, reason),
	); err != nil {
		return &protocolv1.NodeEvidenceEnrollmentResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
				"node evidence enrollment audit failed",
			).Proto(),
		}, nil
	}
	enrollment, err := s.store.EnrollNodeEvidence(ctx, request)
	if err != nil {
		failure := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence enrollment failed")
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceEnroll,
			actor,
			request.ClusterID,
			request.NodeName,
			req.GetAudit(),
			failure,
		)
		return &protocolv1.NodeEvidenceEnrollmentResponse{Decision: failure.Proto()}, nil
	}
	return &protocolv1.NodeEvidenceEnrollmentResponse{
		Enrollment: nodeEvidenceEnrollmentToProto(enrollment),
		Decision:   decision.Proto(),
	}, nil
}

// RevokeNodeEvidence revokes node trust and invalidates verified evidence.
func (s EnrollmentService) RevokeNodeEvidence(
	ctx context.Context,
	req *protocolv1.NodeEvidenceRevocationRequest,
) (*protocolv1.NodeEvidenceRevocationResponse, error) {
	clusterID, nodeName, reason, err := nodeEvidenceRevocationRequestFromProto(req)
	if err != nil {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error())
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceRevoke,
			"",
			clusterID,
			nodeName,
			reqAudit(req),
			decision,
		)
		return &protocolv1.NodeEvidenceRevocationResponse{Decision: decision.Proto()}, nil
	}
	actor, code, err := s.authorize(ctx, clusterID)
	if err != nil {
		decision := Deny(s.policyID, code, err.Error())
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceRevoke,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceRevocationResponse{Decision: decision.Proto()}, nil
	}
	if !s.acceptsCluster(clusterID) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"node evidence cluster is not configured",
		)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceRevoke,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceRevocationResponse{Decision: decision.Proto()}, nil
	}
	if s.store == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
			"node evidence enrollment storage is unavailable",
		)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceRevoke,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceRevocationResponse{Decision: decision.Proto()}, nil
	}
	decision := Allow(s.policyID)
	if err := s.auditEnrollmentDecision(
		ctx,
		enrollmentOperationNodeEvidenceRevoke,
		actor,
		clusterID,
		nodeName,
		req.GetAudit(),
		decisionWithReason(decision, reason),
	); err != nil {
		return &protocolv1.NodeEvidenceRevocationResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
				"node evidence revocation audit failed",
			).Proto(),
		}, nil
	}
	enrollment, err := s.store.RevokeNodeEvidence(ctx, clusterID, nodeName, s.now())
	if err != nil {
		code := protocolv1.ErrorCode_ERROR_CODE_INTERNAL
		message := "node evidence revocation failed"
		if errors.Is(err, nodeevidence.ErrEnrollmentNotFound) ||
			errors.Is(err, nodeevidence.ErrEnrollmentRevoked) {
			code = protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST
			message = err.Error()
		}
		failure := Deny(s.policyID, code, message)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceRevoke,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			failure,
		)
		return &protocolv1.NodeEvidenceRevocationResponse{Decision: failure.Proto()}, nil
	}
	return &protocolv1.NodeEvidenceRevocationResponse{
		Enrollment: nodeEvidenceEnrollmentToProto(enrollment),
		Decision:   decision.Proto(),
	}, nil
}

// ListNodeEvidenceEnrollments returns operator-only node trust diagnostics.
func (s EnrollmentService) ListNodeEvidenceEnrollments(
	ctx context.Context,
	req *protocolv1.NodeEvidenceEnrollmentListRequest,
) (*protocolv1.NodeEvidenceEnrollmentListResponse, error) {
	if req == nil || strings.TrimSpace(req.GetClusterId()) == "" {
		decision := Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, "cluster_id is required")
		_ = s.auditEnrollmentDecision(ctx, enrollmentOperationNodeEvidenceList, "", "", "", reqAudit(req), decision)
		return &protocolv1.NodeEvidenceEnrollmentListResponse{Decision: decision.Proto()}, nil
	}
	clusterID := strings.TrimSpace(req.GetClusterId())
	nodeName := strings.TrimSpace(req.GetNodeName())
	actor, code, err := s.authorize(ctx, clusterID)
	if err != nil {
		decision := Deny(s.policyID, code, err.Error())
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceList,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentListResponse{Decision: decision.Proto()}, nil
	}
	if !s.acceptsCluster(clusterID) {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
			"node evidence cluster is not configured",
		)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceList,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentListResponse{Decision: decision.Proto()}, nil
	}
	if s.store == nil {
		decision := Deny(
			s.policyID,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
			"node evidence enrollment storage is unavailable",
		)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceList,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentListResponse{Decision: decision.Proto()}, nil
	}
	enrollments, err := s.store.ListNodeEvidenceEnrollments(
		ctx,
		clusterID,
		nodeName,
		req.GetIncludeRevoked(),
	)
	if err != nil {
		if errors.Is(err, nodeevidence.ErrEnrollmentNotFound) {
			decision := Allow(s.policyID)
			_ = s.auditEnrollmentDecision(
				ctx,
				enrollmentOperationNodeEvidenceList,
				actor,
				clusterID,
				nodeName,
				req.GetAudit(),
				decision,
			)
			return &protocolv1.NodeEvidenceEnrollmentListResponse{Decision: decision.Proto()}, nil
		}
		code := protocolv1.ErrorCode_ERROR_CODE_INTERNAL
		message := "node evidence enrollment lookup failed"
		decision := Deny(s.policyID, code, message)
		_ = s.auditEnrollmentDecision(
			ctx,
			enrollmentOperationNodeEvidenceList,
			actor,
			clusterID,
			nodeName,
			req.GetAudit(),
			decision,
		)
		return &protocolv1.NodeEvidenceEnrollmentListResponse{Decision: decision.Proto()}, nil
	}
	out := make([]*protocolv1.NodeEvidenceEnrollmentRecord, 0, len(enrollments))
	for _, enrollment := range enrollments {
		out = append(out, nodeEvidenceEnrollmentToProto(enrollment))
	}
	decision := Allow(s.policyID)
	_ = s.auditEnrollmentDecision(
		ctx,
		enrollmentOperationNodeEvidenceList,
		actor,
		clusterID,
		nodeName,
		req.GetAudit(),
		decision,
	)
	return &protocolv1.NodeEvidenceEnrollmentListResponse{
		Enrollments: out,
		Decision:    decision.Proto(),
	}, nil
}

func (s EnrollmentService) authorize(
	ctx context.Context,
	clusterID string,
) (string, protocolv1.ErrorCode, error) {
	certificateHash, err := nodeEvidenceClientCertificateHash(ctx)
	if err != nil {
		return "", protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, errors.New(
			"control-plane operation requires an authenticated client certificate",
		)
	}
	identity, ok := s.identities[certificateHash]
	if !ok || !slices.Contains(identity.Roles, ControlPlaneRoleNodeEvidenceAdmin) {
		return certificateHash, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, errors.New(
			"control-plane identity lacks the node-evidence-admin role",
		)
	}
	if !slices.Contains(identity.ClusterIDs, strings.TrimSpace(clusterID)) {
		return certificateHash, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, errors.New(
			"control-plane identity is not authorized for this cluster",
		)
	}
	return certificateHash, protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED, nil
}

func (s EnrollmentService) auditEnrollmentDecision(
	ctx context.Context,
	operation string,
	actor string,
	clusterID string,
	nodeName string,
	auditContext *protocolv1.AuditContext,
	decision PolicyDecision,
) error {
	if s.auditStore == nil && (s.audit == nil || s.audit.path == "") {
		return errors.New("security audit sink is not configured")
	}
	auditID, err := randomID("audit")
	if err != nil {
		return err
	}
	if actor == "" {
		actor = "unauthenticated"
	}
	event := AuditEvent{
		SchemaVersion: 1,
		AuditID:       auditID,
		Time:          s.now().UTC().Format(time.RFC3339Nano),
		Subject:       actor,
		Actor:         actor,
		Target:        nodeName,
		Operation:     operation,
		ClusterID:     clusterID,
		Decision:      decision.State.String(),
		PolicyID:      decision.PolicyID,
		Reason:        decision.Reason,
		RemoteAddress: remoteAddress(ctx),
		ErrorCode:     auditErrorCode(decision),
	}
	if auditContext != nil {
		event.CorrelationID = strings.TrimSpace(auditContext.GetCorrelationId())
		event.RequestID = strings.TrimSpace(auditContext.GetRequestId())
	}
	if s.auditStore != nil {
		if err := s.auditStore.InsertAuditEvent(ctx, event); err != nil {
			return err
		}
	}
	if s.audit != nil && s.audit.path != "" {
		if err := s.audit.Write(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func (s EnrollmentService) acceptsCluster(clusterID string) bool {
	return s.clusterID == "" || s.clusterID == strings.TrimSpace(clusterID)
}

func (s EnrollmentService) now() time.Time {
	if s.clock == nil {
		return time.Now().UTC()
	}
	return s.clock().UTC()
}

func nodeEvidenceEnrollmentRequestFromProto(
	req *protocolv1.NodeEvidenceEnrollmentRequest,
	now time.Time,
) (nodeevidence.EnrollmentRequest, string, error) {
	if req == nil || req.GetTpmPolicy() == nil {
		return nodeevidence.EnrollmentRequest{}, "", errors.New(
			"node evidence enrollment and TPM policy are required",
		)
	}
	reason, err := normalizeEnrollmentReason(req.GetReason())
	if err != nil {
		return nodeevidence.EnrollmentRequest{}, "", err
	}
	policy, err := tpmPolicyFromProto(req.GetTpmPolicy())
	if err != nil {
		return nodeevidence.EnrollmentRequest{}, "", err
	}
	request, err := nodeevidence.NormalizeEnrollmentRequest(nodeevidence.EnrollmentRequest{
		ClusterID:                  req.GetClusterId(),
		NodeName:                   req.GetNodeName(),
		NodeUID:                    req.GetNodeUid(),
		Provider:                   req.GetProviderId(),
		TPMPolicy:                  policy,
		PublisherCertificateHashes: req.GetPublisherCertificateSha256(),
		EnrolledAt:                 now,
	})
	return request, reason, err
}

func nodeEvidenceRevocationRequestFromProto(
	req *protocolv1.NodeEvidenceRevocationRequest,
) (string, string, string, error) {
	if req == nil {
		return "", "", "", errors.New("node evidence revocation request is required")
	}
	clusterID := strings.TrimSpace(req.GetClusterId())
	nodeName := strings.TrimSpace(req.GetNodeName())
	if clusterID == "" || nodeName == "" {
		return clusterID, nodeName, "", errors.New("cluster_id and node_name are required")
	}
	reason, err := normalizeEnrollmentReason(req.GetReason())
	return clusterID, nodeName, reason, err
}

func normalizeEnrollmentReason(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("reason is required")
	}
	if len(value) > 1024 {
		return "", errors.New("reason exceeds maximum size")
	}
	return value, nil
}

func tpmPolicyFromProto(policy *protocolv1.NodeEvidenceTPMPolicy) (tpmlocal.Policy, error) {
	out := tpmlocal.Policy{
		Mode:                 strings.TrimSpace(policy.GetMode()),
		EnrolledAKPublicHash: strings.TrimSpace(policy.GetEnrolledAkPublicHash()),
		ProviderProfile:      strings.TrimSpace(policy.GetProviderProfile()),
	}
	if pcr := policy.GetPcrPolicy(); pcr != nil {
		indexes := make([]int, 0, len(pcr.GetPcrs()))
		for _, index := range pcr.GetPcrs() {
			if index > 23 {
				return tpmlocal.Policy{}, fmt.Errorf("PCR index %d is out of range", index)
			}
			indexes = append(indexes, int(index))
		}
		out.PCRPolicy = &tpmlocal.PCRPolicy{
			Selection: tpmlocal.PCRSelection{
				Hash: strings.TrimSpace(pcr.GetHash()),
				PCRs: indexes,
			},
			ExpectedDigest: strings.TrimSpace(pcr.GetExpectedDigest()),
			Profile:        strings.TrimSpace(pcr.GetProfile()),
		}
	}
	return out, nil
}

func nodeEvidenceEnrollmentToProto(
	enrollment nodeevidence.Enrollment,
) *protocolv1.NodeEvidenceEnrollmentRecord {
	policy := &protocolv1.NodeEvidenceTPMPolicy{
		Mode:                 enrollment.TPMPolicy.Mode,
		EnrolledAkPublicHash: enrollment.TPMPolicy.EnrolledAKPublicHash,
		ProviderProfile:      enrollment.TPMPolicy.ProviderProfile,
	}
	if pcr := enrollment.TPMPolicy.PCRPolicy; pcr != nil {
		indexes := make([]uint32, 0, len(pcr.Selection.PCRs))
		for _, index := range pcr.Selection.PCRs {
			// #nosec G115 -- persisted policies pass TPM PCR validation before storage.
			indexes = append(indexes, uint32(index))
		}
		policy.PcrPolicy = &protocolv1.NodeEvidencePCRPolicy{
			Hash:           pcr.Selection.Hash,
			Pcrs:           indexes,
			ExpectedDigest: pcr.ExpectedDigest,
			Profile:        pcr.Profile,
		}
	}
	return &protocolv1.NodeEvidenceEnrollmentRecord{
		ClusterId:                  enrollment.ClusterID,
		NodeName:                   enrollment.NodeName,
		NodeUid:                    enrollment.NodeUID,
		ProviderId:                 enrollment.Provider,
		TpmPolicy:                  policy,
		PublisherCertificateSha256: slices.Clone(enrollment.PublisherCertificateHashes),
		Revision:                   enrollment.Revision,
		EnrolledUnixSeconds:        enrollment.EnrolledAt.Unix(),
		UpdatedUnixSeconds:         enrollment.UpdatedAt.Unix(),
		RevokedUnixSeconds:         unixSecondsOrZero(enrollment.RevokedAt),
	}
}

func decisionWithReason(decision PolicyDecision, reason string) PolicyDecision {
	decision.Reason = reason
	return decision
}

func unixSecondsOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}

func cloneControlPlaneIdentities(
	identities map[string]ControlPlaneIdentity,
) map[string]ControlPlaneIdentity {
	cloned := make(map[string]ControlPlaneIdentity, len(identities))
	for certificateHash, identity := range identities {
		cloned[certificateHash] = ControlPlaneIdentity{
			Roles:      slices.Clone(identity.Roles),
			ClusterIDs: slices.Clone(identity.ClusterIDs),
		}
	}
	return cloned
}

type auditRequest interface {
	GetAudit() *protocolv1.AuditContext
}

func reqAudit(request auditRequest) *protocolv1.AuditContext {
	if request == nil {
		return nil
	}
	return request.GetAudit()
}
