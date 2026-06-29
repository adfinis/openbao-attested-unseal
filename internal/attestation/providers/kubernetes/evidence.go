// Package kubernetes verifies Kubernetes workload identity evidence.
package kubernetes

import (
	"encoding/json"
	"errors"
	"fmt"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
	// EvidenceFormat identifies the Kubernetes workload evidence payload shape.
	EvidenceFormat = "openbao-attested-unseal.kubernetes-workload.v1"
	// ClaimNamespace is used for normalized Kubernetes workload claims.
	ClaimNamespace = "kubernetes"
)

// ErrInvalidEvidence indicates malformed Kubernetes workload evidence.
var ErrInvalidEvidence = errors.New("invalid Kubernetes workload evidence")

// EvidencePayload carries the projected service account token to the broker.
type EvidencePayload struct {
	Token string `json:"token"`
}

// NewEvidenceEnvelope creates a Kubernetes workload evidence envelope.
func NewEvidenceEnvelope(challengeID string, token string) (*protocolv1.EvidenceEnvelope, error) {
	payload := EvidencePayload{Token: token}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal Kubernetes evidence: %w", err)
	}
	return &protocolv1.EvidenceEnvelope{
		Provider:    protocolv1.AttestationProvider_ATTESTATION_PROVIDER_KUBERNETES_WORKLOAD,
		Format:      EvidenceFormat,
		Payload:     encoded,
		ChallengeId: challengeID,
	}, nil
}

func decodeEvidencePayload(envelope *protocolv1.EvidenceEnvelope) (EvidencePayload, error) {
	if envelope == nil {
		return EvidencePayload{}, fmt.Errorf("%w: evidence envelope is required", ErrInvalidEvidence)
	}
	if envelope.GetProvider() != protocolv1.AttestationProvider_ATTESTATION_PROVIDER_KUBERNETES_WORKLOAD {
		return EvidencePayload{}, fmt.Errorf("%w: provider is not Kubernetes workload", ErrInvalidEvidence)
	}
	if envelope.GetFormat() != EvidenceFormat {
		return EvidencePayload{}, fmt.Errorf("%w: unsupported evidence format", ErrInvalidEvidence)
	}
	if len(envelope.GetPayload()) == 0 {
		return EvidencePayload{}, fmt.Errorf("%w: payload is required", ErrInvalidEvidence)
	}
	if len(envelope.GetPayload()) > protocolv1.MaxProtoPayloadSize {
		return EvidencePayload{}, fmt.Errorf("%w: payload exceeds maximum size", ErrInvalidEvidence)
	}
	var payload EvidencePayload
	if err := json.Unmarshal(envelope.GetPayload(), &payload); err != nil {
		return EvidencePayload{}, fmt.Errorf("%w: decode payload: %w", ErrInvalidEvidence, err)
	}
	if payload.Token == "" {
		return EvidencePayload{}, fmt.Errorf("%w: token is required", ErrInvalidEvidence)
	}
	return payload, nil
}
