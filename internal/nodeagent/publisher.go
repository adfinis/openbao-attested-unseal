// Package nodeagent contains node evidence publishing primitives.
package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
)

var (
	// ErrInvalidPublishRequest indicates a malformed node evidence publish request.
	ErrInvalidPublishRequest = errors.New("invalid node evidence publish request")
	// ErrInvalidProviderEvidence indicates a provider returned unusable node evidence metadata.
	ErrInvalidProviderEvidence = errors.New("invalid node evidence provider result")
)

// PublishRequest identifies one Kubernetes node evidence publication.
type PublishRequest struct {
	ClusterID string
	NodeName  string
	NodeUID   string
	TTL       time.Duration
}

// ProviderEvidence is untrusted raw provider evidence sent to the broker.
type ProviderEvidence struct {
	Format  string
	Payload []byte
}

// Provider collects raw node evidence for a broker-issued challenge.
type Provider interface {
	ProviderID() string
	CollectNodeEvidence(context.Context, PublishRequest, nodeevidence.Challenge) (ProviderEvidence, error)
}

// Publisher requests a challenge, collects raw evidence, and submits it for broker verification.
type Publisher struct {
	Client   nodeevidence.PublisherClient
	Provider Provider
	Clock    func() time.Time
}

// Publish returns the sanitized record produced after broker-side verification.
func (p Publisher) Publish(ctx context.Context, request PublishRequest) (nodeevidence.Evidence, error) {
	request, err := normalizePublishRequest(request)
	if err != nil {
		return nodeevidence.Evidence{}, err
	}
	if p.Client == nil {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: client is required", ErrInvalidPublishRequest)
	}
	if p.Provider == nil {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: provider is required", ErrInvalidPublishRequest)
	}
	providerID := strings.TrimSpace(p.Provider.ProviderID())
	if providerID == "" {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: provider_id is required", ErrInvalidProviderEvidence)
	}
	challenge, err := p.Client.RequestNodeEvidenceChallenge(ctx, nodeevidence.ChallengeRequest{
		ClusterID: request.ClusterID,
		NodeName:  request.NodeName,
		NodeUID:   request.NodeUID,
		Provider:  providerID,
	})
	if err != nil {
		return nodeevidence.Evidence{}, fmt.Errorf("request node evidence challenge: %w", err)
	}
	challenge, err = nodeevidence.NormalizeChallenge(challenge)
	if err != nil {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: %v", ErrInvalidProviderEvidence, err)
	}
	if !challenge.ExpiresAt.After(p.now()) {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: broker challenge is expired", ErrInvalidProviderEvidence)
	}
	providerEvidence, err := p.Provider.CollectNodeEvidence(ctx, request, challenge)
	if err != nil {
		return nodeevidence.Evidence{}, fmt.Errorf("collect node evidence: %w", err)
	}
	providerEvidence = normalizeProviderEvidence(providerEvidence)
	if providerEvidence.Format == "" || len(providerEvidence.Payload) == 0 {
		return nodeevidence.Evidence{}, fmt.Errorf(
			"%w: format and payload are required",
			ErrInvalidProviderEvidence,
		)
	}
	evidence, err := p.Client.SubmitNodeEvidence(ctx, nodeevidence.Submission{
		ClusterID:    request.ClusterID,
		NodeName:     request.NodeName,
		NodeUID:      request.NodeUID,
		Provider:     providerID,
		Format:       providerEvidence.Format,
		Payload:      providerEvidence.Payload,
		ChallengeID:  challenge.ID,
		RequestedTTL: request.TTL,
	})
	if err != nil {
		return nodeevidence.Evidence{}, fmt.Errorf("publish node evidence: %w", err)
	}
	return evidence, nil
}

func (p Publisher) now() time.Time {
	if p.Clock == nil {
		return time.Now().UTC()
	}
	return p.Clock().UTC()
}

func normalizePublishRequest(request PublishRequest) (PublishRequest, error) {
	request.ClusterID = strings.TrimSpace(request.ClusterID)
	request.NodeName = strings.TrimSpace(request.NodeName)
	request.NodeUID = strings.TrimSpace(request.NodeUID)
	if request.ClusterID == "" || request.NodeName == "" {
		return PublishRequest{}, fmt.Errorf("%w: cluster_id and node_name are required", ErrInvalidPublishRequest)
	}
	if request.TTL <= 0 {
		return PublishRequest{}, fmt.Errorf("%w: ttl must be greater than zero", ErrInvalidPublishRequest)
	}
	return request, nil
}

func normalizeProviderEvidence(evidence ProviderEvidence) ProviderEvidence {
	return ProviderEvidence{
		Format:  strings.TrimSpace(evidence.Format),
		Payload: slices.Clone(evidence.Payload),
	}
}

// FakeLocalProvider produces deterministic fake-local node evidence for tests
// and local labs. It is not a production security boundary.
type FakeLocalProvider struct{}

// ProviderID returns the explicit development-only provider identifier.
func (FakeLocalProvider) ProviderID() string {
	return nodeevidence.ProviderFakeLocal
}

// CollectNodeEvidence returns deterministic challenge-bound fake-local evidence.
func (FakeLocalProvider) CollectNodeEvidence(
	_ context.Context,
	request PublishRequest,
	challenge nodeevidence.Challenge,
) (ProviderEvidence, error) {
	request, err := normalizePublishRequest(request)
	if err != nil {
		return ProviderEvidence{}, err
	}
	payload, err := nodeevidence.FakeLocalPayload(nodeevidence.ChallengeRequest{
		ClusterID: request.ClusterID,
		NodeName:  request.NodeName,
		NodeUID:   request.NodeUID,
		Provider:  nodeevidence.ProviderFakeLocal,
	}, challenge)
	if err != nil {
		return ProviderEvidence{}, err
	}
	return ProviderEvidence{
		Format:  nodeevidence.FormatFakeLocal,
		Payload: payload,
	}, nil
}
