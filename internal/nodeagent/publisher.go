// Package nodeagent contains node evidence publishing primitives.
package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
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

// ProviderEvidence is the provider-specific metadata that can be stored safely
// in the broker node evidence record.
type ProviderEvidence struct {
	ProviderID   string
	EvidenceHash string
}

// Provider collects or derives node evidence metadata for one node.
type Provider interface {
	CollectNodeEvidence(context.Context, PublishRequest) (ProviderEvidence, error)
}

// Publisher writes fresh node evidence into the broker evidence store.
type Publisher struct {
	Writer   broker.NodeEvidenceWriter
	Provider Provider
	Clock    func() time.Time
}

// Publish collects provider metadata and writes one fresh broker node evidence
// record. The returned record is the same sanitized metadata stored in the broker.
func (p Publisher) Publish(ctx context.Context, request PublishRequest) (broker.NodeEvidence, error) {
	request, err := normalizePublishRequest(request)
	if err != nil {
		return broker.NodeEvidence{}, err
	}
	if p.Writer == nil {
		return broker.NodeEvidence{}, fmt.Errorf("%w: writer is required", ErrInvalidPublishRequest)
	}
	if p.Provider == nil {
		return broker.NodeEvidence{}, fmt.Errorf("%w: provider is required", ErrInvalidPublishRequest)
	}
	now := p.now()
	providerEvidence, err := p.Provider.CollectNodeEvidence(ctx, request)
	if err != nil {
		return broker.NodeEvidence{}, fmt.Errorf("collect node evidence: %w", err)
	}
	providerEvidence = normalizeProviderEvidence(providerEvidence)
	if providerEvidence.ProviderID == "" || providerEvidence.EvidenceHash == "" {
		return broker.NodeEvidence{}, fmt.Errorf(
			"%w: provider_id and evidence_hash are required",
			ErrInvalidProviderEvidence,
		)
	}
	evidence := broker.NodeEvidence{
		ClusterID:    request.ClusterID,
		NodeName:     request.NodeName,
		NodeUID:      request.NodeUID,
		Provider:     providerEvidence.ProviderID,
		EvidenceHash: providerEvidence.EvidenceHash,
		CollectedAt:  now,
		ExpiresAt:    now.Add(request.TTL),
	}
	if err := p.Writer.PutNodeEvidence(ctx, evidence); err != nil {
		return broker.NodeEvidence{}, fmt.Errorf("publish node evidence: %w", err)
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
		ProviderID:   strings.TrimSpace(evidence.ProviderID),
		EvidenceHash: strings.TrimSpace(evidence.EvidenceHash),
	}
}

// FakeLocalProvider produces deterministic fake-local node evidence for tests
// and local labs. It is not a production security boundary.
type FakeLocalProvider struct{}

// CollectNodeEvidence returns deterministic fake-local evidence metadata.
func (FakeLocalProvider) CollectNodeEvidence(_ context.Context, request PublishRequest) (ProviderEvidence, error) {
	request, err := normalizePublishRequest(request)
	if err != nil {
		return ProviderEvidence{}, err
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		request.ClusterID,
		request.NodeName,
		request.NodeUID,
		broker.NodeEvidenceProviderFakeLocal,
	}, "\x00")))
	return ProviderEvidence{
		ProviderID:   broker.NodeEvidenceProviderFakeLocal,
		EvidenceHash: hex.EncodeToString(sum[:]),
	}, nil
}
