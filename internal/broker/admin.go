package broker

import (
	"context"
	"errors"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
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
	nodeEvidenceRetention        time.Duration
	policyID                     string
	allowFakeNodeEvidencePublish bool
	clock                        func() time.Time
}

// NewAdminService creates the broker admin service.
func NewAdminService(
	nodeEvidence NodeEvidenceStore,
	policyID string,
	allowFakeNodeEvidencePublish bool,
) AdminService {
	return newAdminService(
		nodeEvidence,
		policyID,
		allowFakeNodeEvidencePublish,
		DefaultKubernetesNodeEvidenceRetention,
		nil,
		nil,
	)
}

func newAdminService(
	nodeEvidence NodeEvidenceStore,
	policyID string,
	allowFakeNodeEvidencePublish bool,
	nodeEvidenceRetention time.Duration,
	auditStore adminAuditStore,
	audit *FileAuditSink,
) AdminService {
	return AdminService{
		nodeEvidence:                 nodeEvidence,
		auditStore:                   auditStore,
		audit:                        audit,
		nodeEvidenceRetention:        nodeEvidenceRetention,
		policyID:                     policyID,
		allowFakeNodeEvidencePublish: allowFakeNodeEvidencePublish,
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
