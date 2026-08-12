package brokeradmin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

var (
	// ErrEnrollNodeEvidence indicates an enrollment control RPC failed.
	ErrEnrollNodeEvidence = errors.New("enroll node evidence")
	// ErrRevokeNodeEvidence indicates a revocation control RPC failed.
	ErrRevokeNodeEvidence = errors.New("revoke node evidence")
	// ErrListNodeEvidenceEnrollments indicates an enrollment lookup RPC failed.
	ErrListNodeEvidenceEnrollments = errors.New("list node evidence enrollments")
)

// NodeEnrollmentClient invokes authenticated broker-owned node trust operations.
type NodeEnrollmentClient struct {
	Client protocolv1.EnrollmentServiceClient
}

// Enroll creates or replaces one node trust enrollment.
func (c NodeEnrollmentClient) Enroll(
	ctx context.Context,
	request nodeevidence.EnrollmentRequest,
	reason string,
	audit *protocolv1.AuditContext,
) (nodeevidence.Enrollment, error) {
	if c.Client == nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("%w: enrollment client is required", ErrEnrollNodeEvidence)
	}
	if request.EnrolledAt.IsZero() {
		request.EnrolledAt = time.Now().UTC()
	}
	request, err := nodeevidence.NormalizeEnrollmentRequest(request)
	if err != nil {
		return nodeevidence.Enrollment{}, err
	}
	response, err := c.Client.EnrollNodeEvidence(ctx, &protocolv1.NodeEvidenceEnrollmentRequest{
		ClusterId:                  request.ClusterID,
		NodeName:                   request.NodeName,
		NodeUid:                    request.NodeUID,
		ProviderId:                 request.Provider,
		TpmPolicy:                  tpmPolicyToProto(request.TPMPolicy),
		PublisherCertificateSha256: request.PublisherCertificateHashes,
		Reason:                     strings.TrimSpace(reason),
		Audit:                      audit,
	})
	if err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("%w: %w", ErrEnrollNodeEvidence, err)
	}
	if err := RequireAllowDecision(response.GetDecision(), "enroll node evidence"); err != nil {
		return nodeevidence.Enrollment{}, err
	}
	return nodeEnrollmentFromProto(response.GetEnrollment())
}

// Revoke revokes node trust and invalidates cached verified evidence.
func (c NodeEnrollmentClient) Revoke(
	ctx context.Context,
	clusterID string,
	nodeName string,
	reason string,
	audit *protocolv1.AuditContext,
) (nodeevidence.Enrollment, error) {
	if c.Client == nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("%w: enrollment client is required", ErrRevokeNodeEvidence)
	}
	response, err := c.Client.RevokeNodeEvidence(ctx, &protocolv1.NodeEvidenceRevocationRequest{
		ClusterId: strings.TrimSpace(clusterID),
		NodeName:  strings.TrimSpace(nodeName),
		Reason:    strings.TrimSpace(reason),
		Audit:     audit,
	})
	if err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("%w: %w", ErrRevokeNodeEvidence, err)
	}
	if err := RequireAllowDecision(response.GetDecision(), "revoke node evidence"); err != nil {
		return nodeevidence.Enrollment{}, err
	}
	return nodeEnrollmentFromProto(response.GetEnrollment())
}

// List returns node trust enrollment diagnostics.
func (c NodeEnrollmentClient) List(
	ctx context.Context,
	clusterID string,
	nodeName string,
	includeRevoked bool,
	audit *protocolv1.AuditContext,
) ([]nodeevidence.Enrollment, error) {
	if c.Client == nil {
		return nil, fmt.Errorf("%w: enrollment client is required", ErrListNodeEvidenceEnrollments)
	}
	response, err := c.Client.ListNodeEvidenceEnrollments(ctx, &protocolv1.NodeEvidenceEnrollmentListRequest{
		ClusterId:      strings.TrimSpace(clusterID),
		NodeName:       strings.TrimSpace(nodeName),
		IncludeRevoked: includeRevoked,
		Audit:          audit,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrListNodeEvidenceEnrollments, err)
	}
	if err := RequireAllowDecision(response.GetDecision(), "list node evidence enrollments"); err != nil {
		return nil, err
	}
	out := make([]nodeevidence.Enrollment, 0, len(response.GetEnrollments()))
	for _, record := range response.GetEnrollments() {
		enrollment, err := nodeEnrollmentFromProto(record)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrListNodeEvidenceEnrollments, err)
		}
		out = append(out, enrollment)
	}
	return out, nil
}

func tpmPolicyToProto(policy tpmlocal.Policy) *protocolv1.NodeEvidenceTPMPolicy {
	out := &protocolv1.NodeEvidenceTPMPolicy{
		Mode:                 policy.Mode,
		EnrolledAkPublicHash: policy.EnrolledAKPublicHash,
		ProviderProfile:      policy.ProviderProfile,
	}
	if pcr := policy.PCRPolicy; pcr != nil {
		indexes := make([]uint32, 0, len(pcr.Selection.PCRs))
		for _, index := range pcr.Selection.PCRs {
			// #nosec G115 -- client requests pass TPM PCR validation before mapping.
			indexes = append(indexes, uint32(index))
		}
		out.PcrPolicy = &protocolv1.NodeEvidencePCRPolicy{
			Hash:           pcr.Selection.Hash,
			Pcrs:           indexes,
			ExpectedDigest: pcr.ExpectedDigest,
			Profile:        pcr.Profile,
		}
	}
	return out
}

func nodeEnrollmentFromProto(
	record *protocolv1.NodeEvidenceEnrollmentRecord,
) (nodeevidence.Enrollment, error) {
	if record == nil || record.GetTpmPolicy() == nil {
		return nodeevidence.Enrollment{}, errors.New("node evidence enrollment response is incomplete")
	}
	policy := tpmlocal.Policy{
		Mode:                 record.GetTpmPolicy().GetMode(),
		EnrolledAKPublicHash: record.GetTpmPolicy().GetEnrolledAkPublicHash(),
		ProviderProfile:      record.GetTpmPolicy().GetProviderProfile(),
	}
	if pcr := record.GetTpmPolicy().GetPcrPolicy(); pcr != nil {
		indexes := make([]int, 0, len(pcr.GetPcrs()))
		for _, index := range pcr.GetPcrs() {
			if index > 23 {
				return nodeevidence.Enrollment{}, fmt.Errorf("invalid response PCR index %d", index)
			}
			indexes = append(indexes, int(index))
		}
		policy.PCRPolicy = &tpmlocal.PCRPolicy{
			Selection: tpmlocal.PCRSelection{
				Hash: pcr.GetHash(),
				PCRs: indexes,
			},
			ExpectedDigest: pcr.GetExpectedDigest(),
			Profile:        pcr.GetProfile(),
		}
	}
	return nodeevidence.NormalizeEnrollment(nodeevidence.Enrollment{
		ClusterID:                  record.GetClusterId(),
		NodeName:                   record.GetNodeName(),
		NodeUID:                    record.GetNodeUid(),
		Provider:                   record.GetProviderId(),
		TPMPolicy:                  policy,
		PublisherCertificateHashes: record.GetPublisherCertificateSha256(),
		Revision:                   record.GetRevision(),
		EnrolledAt:                 time.Unix(record.GetEnrolledUnixSeconds(), 0).UTC(),
		UpdatedAt:                  time.Unix(record.GetUpdatedUnixSeconds(), 0).UTC(),
		RevokedAt:                  timeFromUnixOrZero(record.GetRevokedUnixSeconds()),
	})
}

func timeFromUnixOrZero(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}
