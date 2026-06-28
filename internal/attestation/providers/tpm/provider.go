package tpm

import (
	"context"
	"fmt"
	"strconv"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

const ClaimNamespace = "tpm"

// Provider collects and verifies TPM quote evidence for the generic attestation envelope.
type Provider struct {
	Device tpmlocal.Device
}

// Collect creates an evidence envelope by quoting the supplied challenge nonce.
func (p Provider) Collect(
	ctx context.Context,
	challengeID string,
	nonce []byte,
	selection tpmlocal.PCRSelection,
	platformHint string,
) (*protocolv1.EvidenceEnvelope, error) {
	rwc, err := p.Device.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rwc.Close()
	}()
	ak, err := tpmlocal.CreateAK(rwc)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = ak.Flush(rwc)
	}()
	evidence, err := tpmlocal.CollectQuote(rwc, ak, challengeID, nonce, selection, platformHint)
	if err != nil {
		return nil, err
	}
	payload, err := evidence.Marshal()
	if err != nil {
		return nil, err
	}
	return &protocolv1.EvidenceEnvelope{
		Provider:    protocolv1.AttestationProvider_ATTESTATION_PROVIDER_TPM2_QUOTE,
		Format:      tpmlocal.EvidenceFormat,
		Payload:     payload,
		ChallengeId: challengeID,
	}, nil
}

// Verify validates a TPM evidence envelope and returns it with normalized claims populated.
func Verify(
	envelope *protocolv1.EvidenceEnvelope,
	expectedNonce []byte,
	policy tpmlocal.Policy,
) (*protocolv1.EvidenceEnvelope, tpmlocal.Claims, error) {
	if envelope == nil {
		return nil, tpmlocal.Claims{}, fmt.Errorf("%w: evidence envelope is required", tpmlocal.ErrInvalidEvidence)
	}
	if envelope.GetProvider() != protocolv1.AttestationProvider_ATTESTATION_PROVIDER_TPM2_QUOTE {
		return nil, tpmlocal.Claims{}, fmt.Errorf("%w: provider is not TPM2_QUOTE", tpmlocal.ErrInvalidEvidence)
	}
	if envelope.GetFormat() != tpmlocal.EvidenceFormat {
		return nil, tpmlocal.Claims{}, fmt.Errorf("%w: unsupported TPM evidence format", tpmlocal.ErrInvalidEvidence)
	}
	evidence, err := tpmlocal.UnmarshalEvidence(envelope.GetPayload())
	if err != nil {
		return nil, tpmlocal.Claims{}, err
	}
	if evidence.ChallengeID != envelope.GetChallengeId() {
		return nil, tpmlocal.Claims{}, fmt.Errorf("%w: challenge ID mismatch", tpmlocal.ErrInvalidEvidence)
	}
	claims, err := tpmlocal.EvaluatePolicy(evidence, expectedNonce, policy)
	if err != nil {
		return nil, tpmlocal.Claims{}, err
	}
	out := &protocolv1.EvidenceEnvelope{
		Provider:         envelope.GetProvider(),
		Format:           envelope.GetFormat(),
		Payload:          envelope.GetPayload(),
		ChallengeId:      envelope.GetChallengeId(),
		NormalizedClaims: ClaimsToProto(claims),
	}
	return out, claims, nil
}

// ClaimsToProto maps verified TPM facts into the generic claim envelope.
func ClaimsToProto(claims tpmlocal.Claims) []*protocolv1.Claim {
	return []*protocolv1.Claim{
		{Namespace: "dev", Name: "subject", Value: claims.SubjectFingerprint},
		{Namespace: ClaimNamespace, Name: "ak_public_hash", Value: claims.AKPublicHash},
		{Namespace: ClaimNamespace, Name: "pcr_hash", Value: claims.PCRSelection.Hash},
		{Namespace: ClaimNamespace, Name: "pcrs", Value: fmt.Sprint(claims.PCRSelection.PCRs)},
		{Namespace: ClaimNamespace, Name: "pcr_digest", Value: claims.PCRDigest},
		{Namespace: ClaimNamespace, Name: "fresh", Value: strconv.FormatBool(claims.Fresh)},
		{Namespace: ClaimNamespace, Name: "secureboot", Value: strconv.FormatBool(claims.SecureBoot)},
		{Namespace: ClaimNamespace, Name: "policy_mode", Value: claims.PolicyMode},
		{Namespace: ClaimNamespace, Name: "provider_profile", Value: claims.ProviderProfile},
	}
}
