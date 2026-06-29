package broker

import (
	"context"
	"errors"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// AdminService implements broker-local administrative APIs.
type AdminService struct {
	protocolv1.UnimplementedAdminServiceServer
	nodeEvidence                 NodeEvidenceStore
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
	return AdminService{
		nodeEvidence:                 nodeEvidence,
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
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
				"node evidence storage is not configured",
			).Proto(),
		}, nil
	}
	if req == nil {
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"node evidence request is required",
			).Proto(),
		}, nil
	}
	if !s.allowFakeNodeEvidencePublish {
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
				"fake node evidence publish is disabled",
			).Proto(),
		}, nil
	}
	if providerID := nodeEvidenceProviderID(req.GetEvidence()); providerID != NodeEvidenceProviderFakeLocal {
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"only fake-local node evidence can be published through this beta admin API",
			).Proto(),
		}, nil
	}
	evidence, err := nodeEvidenceFromProto(req.GetEvidence())
	if err != nil {
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error()).Proto(),
		}, nil
	}
	if err := s.nodeEvidence.PutNodeEvidence(ctx, evidence); err != nil {
		return &protocolv1.NodeEvidencePublishResponse{
			Decision: Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, err.Error()).Proto(),
		}, nil
	}
	return &protocolv1.NodeEvidencePublishResponse{
		Evidence: nodeEvidenceToProto(evidence, s.now()),
		Decision: Allow(s.policyID).Proto(),
	}, nil
}

// ListNodeEvidence returns stored node evidence records for diagnostics.
func (s AdminService) ListNodeEvidence(
	ctx context.Context,
	req *protocolv1.NodeEvidenceListRequest,
) (*protocolv1.NodeEvidenceListResponse, error) {
	if s.nodeEvidence == nil {
		return &protocolv1.NodeEvidenceListResponse{
			Decision: Deny(
				s.policyID,
				protocolv1.ErrorCode_ERROR_CODE_INTERNAL,
				"node evidence storage is not configured",
			).Proto(),
		}, nil
	}
	if req == nil || req.GetClusterId() == "" {
		return &protocolv1.NodeEvidenceListResponse{
			Decision: Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, "cluster_id is required").Proto(),
		}, nil
	}
	records, err := s.nodeEvidence.ListNodeEvidence(ctx, req.GetClusterId(), req.GetNodeName())
	if err != nil {
		if errors.Is(err, ErrNodeEvidenceNotFound) {
			return &protocolv1.NodeEvidenceListResponse{
				Decision: Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED, "node evidence is missing").Proto(),
			}, nil
		}
		return &protocolv1.NodeEvidenceListResponse{
			Decision: Deny(s.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "node evidence lookup failed").Proto(),
		}, nil
	}
	out := make([]*protocolv1.NodeEvidenceRecord, 0, len(records))
	now := s.now()
	for _, evidence := range records {
		out = append(out, nodeEvidenceToProto(evidence, now))
	}
	return &protocolv1.NodeEvidenceListResponse{
		Evidence: out,
		Decision: Allow(s.policyID).Proto(),
	}, nil
}

func (s AdminService) now() time.Time {
	if s.clock == nil {
		return time.Now()
	}
	return s.clock()
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
