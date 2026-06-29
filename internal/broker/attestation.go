package broker

import (
	"context"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// VerifiedEvidence is the broker-local result of provider-specific evidence verification.
type VerifiedEvidence struct {
	Subject  string
	Workload WorkloadIdentity
}

// WorkloadIdentity contains workload placement facts that can be correlated with node evidence.
type WorkloadIdentity struct {
	Namespace      string
	ServiceAccount string
	PodName        string
	PodUID         string
	NodeName       string
	NodeUID        string
}

// EvidenceVerifier validates attestation evidence before policy evaluation.
type EvidenceVerifier interface {
	VerifyEvidence(context.Context, *protocolv1.EvidenceEnvelope) (VerifiedEvidence, error)
}

// DevelopmentEvidenceVerifier preserves the M2 development-subject behavior.
type DevelopmentEvidenceVerifier struct{}

// VerifyEvidence reads the development subject claim without provider-specific checks.
func (DevelopmentEvidenceVerifier) VerifyEvidence(
	_ context.Context,
	evidence *protocolv1.EvidenceEnvelope,
) (VerifiedEvidence, error) {
	return VerifiedEvidence{Subject: subjectFromEvidence(evidence)}, nil
}
