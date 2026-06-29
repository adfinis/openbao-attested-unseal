package broker

import (
	"context"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// KubernetesEvidenceVerifier adapts Kubernetes workload verification to broker policy input.
type KubernetesEvidenceVerifier struct {
	Verifier k8sprovider.Verifier
}

// NewKubernetesEvidenceVerifier maps broker Kubernetes config into the provider verifier.
func NewKubernetesEvidenceVerifier(
	reviewer k8sprovider.TokenReviewer,
	config KubernetesConfig,
) KubernetesEvidenceVerifier {
	return NewKubernetesEvidenceVerifierWithPodLookup(reviewer, nil, config)
}

// NewKubernetesEvidenceVerifierWithPodLookup maps config and pod lookup into the provider verifier.
func NewKubernetesEvidenceVerifierWithPodLookup(
	reviewer k8sprovider.TokenReviewer,
	podLookup k8sprovider.PodLookup,
	config KubernetesConfig,
) KubernetesEvidenceVerifier {
	return KubernetesEvidenceVerifier{
		Verifier: k8sprovider.Verifier{
			Reviewer:  reviewer,
			PodLookup: podLookup,
			Config: k8sprovider.VerifierConfig{
				Audience:          config.TokenReviewAudience,
				Namespace:         config.Namespace,
				ServiceAccount:    config.ServiceAccount,
				RequirePodBinding: config.RequirePodBoundToken(),
			},
		},
	}
}

// VerifyEvidence validates Kubernetes workload evidence and returns the policy subject.
func (v KubernetesEvidenceVerifier) VerifyEvidence(
	ctx context.Context,
	evidence *protocolv1.EvidenceEnvelope,
) (VerifiedEvidence, error) {
	_, claims, err := v.Verifier.Verify(ctx, evidence)
	if err != nil {
		return VerifiedEvidence{}, err
	}
	return VerifiedEvidence{
		Subject: claims.Subject,
		Workload: WorkloadIdentity{
			Namespace:      claims.Namespace,
			ServiceAccount: claims.ServiceAccount,
			PodName:        claims.PodName,
			PodUID:         claims.PodUID,
			NodeName:       claims.NodeName,
			NodeUID:        claims.NodeUID,
		},
	}, nil
}
