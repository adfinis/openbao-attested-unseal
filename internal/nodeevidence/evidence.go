// Package nodeevidence defines verified node-evidence records and persistence ports.
package nodeevidence

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound indicates that no node evidence is stored for a workload node.
	ErrNotFound = errors.New("node evidence not found")
	// ErrStale indicates that stored node evidence is no longer fresh enough for policy.
	ErrStale = errors.New("node evidence stale")
	// ErrInvalid indicates that a node evidence record is incomplete or malformed.
	ErrInvalid = errors.New("node evidence invalid")
)

const (
	// ProviderFakeLocal identifies synthetic node evidence for tests and local labs.
	ProviderFakeLocal = "fake-local"
	// ProviderTPM2Quote identifies raw generic TPM quote submissions verified by the broker.
	ProviderTPM2Quote = "generic-tpm2-quote"
	// FormatFakeLocal identifies challenge-bound synthetic evidence for tests and local labs.
	FormatFakeLocal = "openbao-attested-unseal.fake-local.v1"
)

// ChallengeRequest identifies the node and provider that will collect fresh evidence.
type ChallengeRequest struct {
	ClusterID string
	NodeName  string
	NodeUID   string
	Provider  string
}

// Challenge is broker-issued, single-use replay-prevention state for one evidence submission.
type Challenge struct {
	ID        string
	Nonce     []byte
	ExpiresAt time.Time
}

// Submission is untrusted provider evidence sent to the broker for verification.
type Submission struct {
	ClusterID    string
	NodeName     string
	NodeUID      string
	Provider     string
	Format       string
	Payload      []byte
	ChallengeID  string
	RequestedTTL time.Duration
}

// Evidence records broker-trusted evidence for one node.
type Evidence struct {
	ClusterID    string
	NodeName     string
	NodeUID      string
	Provider     string
	EvidenceHash string
	CollectedAt  time.Time
	ExpiresAt    time.Time
}

// Reader returns fresh node evidence for workload-to-node correlation.
type Reader interface {
	FreshNodeEvidence(ctx context.Context, clusterID string, nodeName string, now time.Time) (Evidence, error)
}

// Writer stores node evidence after broker verification.
type Writer interface {
	PutNodeEvidence(ctx context.Context, evidence Evidence) error
}

// Repository stores and reads node evidence records.
type Repository interface {
	Reader
	Writer
	NodeEvidence(ctx context.Context, clusterID string, nodeName string) (Evidence, error)
	ListNodeEvidence(ctx context.Context, clusterID string, nodeName string) ([]Evidence, error)
	PruneNodeEvidence(ctx context.Context, clusterID string, expiredBefore time.Time) (int64, error)
}

// Challenger requests single-use broker challenges for evidence collection.
type Challenger interface {
	RequestNodeEvidenceChallenge(context.Context, ChallengeRequest) (Challenge, error)
}

// Submitter sends untrusted evidence to the broker and returns its verified projection.
type Submitter interface {
	SubmitNodeEvidence(context.Context, Submission) (Evidence, error)
}

// PublisherClient is the client-side port used by node evidence publishers.
type PublisherClient interface {
	Challenger
	Submitter
}

// MemoryRepository is a process-local node-evidence repository for tests and development.
type MemoryRepository struct {
	mu      sync.RWMutex
	records map[evidenceKey]Evidence
}

type evidenceKey struct {
	clusterID string
	nodeName  string
}

// NewMemoryRepository creates an empty process-local node-evidence repository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{records: make(map[evidenceKey]Evidence)}
}

// PutNodeEvidence stores or replaces cached node evidence.
func (r *MemoryRepository) PutNodeEvidence(_ context.Context, evidence Evidence) error {
	if r == nil {
		return fmt.Errorf("%w: repository is nil", ErrInvalid)
	}
	normalized, err := Normalize(evidence)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[evidenceKey{clusterID: normalized.ClusterID, nodeName: normalized.NodeName}] = normalized
	return nil
}

// FreshNodeEvidence returns evidence if it exists and has not expired.
func (r *MemoryRepository) FreshNodeEvidence(
	_ context.Context,
	clusterID string,
	nodeName string,
	now time.Time,
) (Evidence, error) {
	if r == nil {
		return Evidence{}, ErrNotFound
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := evidenceKey{clusterID: strings.TrimSpace(clusterID), nodeName: strings.TrimSpace(nodeName)}
	r.mu.RLock()
	evidence, ok := r.records[key]
	r.mu.RUnlock()
	if !ok {
		return Evidence{}, ErrNotFound
	}
	if !evidence.ExpiresAt.After(now) {
		return evidence, ErrStale
	}
	return evidence, nil
}

// NodeEvidence returns evidence without enforcing freshness.
func (r *MemoryRepository) NodeEvidence(
	_ context.Context,
	clusterID string,
	nodeName string,
) (Evidence, error) {
	if r == nil {
		return Evidence{}, ErrNotFound
	}
	key := evidenceKey{clusterID: strings.TrimSpace(clusterID), nodeName: strings.TrimSpace(nodeName)}
	r.mu.RLock()
	evidence, ok := r.records[key]
	r.mu.RUnlock()
	if !ok {
		return Evidence{}, ErrNotFound
	}
	return evidence, nil
}

// ListNodeEvidence returns evidence for one cluster, optionally filtered by node name.
func (r *MemoryRepository) ListNodeEvidence(
	_ context.Context,
	clusterID string,
	nodeName string,
) ([]Evidence, error) {
	if r == nil {
		return nil, ErrNotFound
	}
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Evidence, 0, len(r.records))
	for key, evidence := range r.records {
		if key.clusterID != clusterID || (nodeName != "" && key.nodeName != nodeName) {
			continue
		}
		out = append(out, evidence)
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// PruneNodeEvidence deletes evidence that expired before the supplied cutoff.
func (r *MemoryRepository) PruneNodeEvidence(
	_ context.Context,
	clusterID string,
	expiredBefore time.Time,
) (int64, error) {
	if r == nil {
		return 0, ErrNotFound
	}
	clusterID = strings.TrimSpace(clusterID)
	if expiredBefore.IsZero() {
		expiredBefore = time.Now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var removed int64
	for key, evidence := range r.records {
		if key.clusterID == clusterID && evidence.ExpiresAt.Before(expiredBefore) {
			delete(r.records, key)
			removed++
		}
	}
	return removed, nil
}

// Normalize validates and canonicalizes a verified node-evidence record.
func Normalize(evidence Evidence) (Evidence, error) {
	evidence.ClusterID = strings.TrimSpace(evidence.ClusterID)
	evidence.NodeName = strings.TrimSpace(evidence.NodeName)
	evidence.NodeUID = strings.TrimSpace(evidence.NodeUID)
	evidence.Provider = strings.TrimSpace(evidence.Provider)
	evidence.EvidenceHash = strings.TrimSpace(evidence.EvidenceHash)
	if evidence.ClusterID == "" || evidence.NodeName == "" || evidence.Provider == "" || evidence.EvidenceHash == "" {
		return Evidence{}, fmt.Errorf(
			"%w: cluster_id, node_name, provider, and evidence_hash are required",
			ErrInvalid,
		)
	}
	if evidence.CollectedAt.IsZero() || evidence.ExpiresAt.IsZero() {
		return Evidence{}, fmt.Errorf("%w: collected_at and expires_at are required", ErrInvalid)
	}
	if !evidence.ExpiresAt.After(evidence.CollectedAt) {
		return Evidence{}, fmt.Errorf("%w: expires_at must be after collected_at", ErrInvalid)
	}
	return evidence, nil
}

// NormalizeChallengeRequest validates and canonicalizes a challenge request.
func NormalizeChallengeRequest(request ChallengeRequest) (ChallengeRequest, error) {
	request.ClusterID = strings.TrimSpace(request.ClusterID)
	request.NodeName = strings.TrimSpace(request.NodeName)
	request.NodeUID = strings.TrimSpace(request.NodeUID)
	request.Provider = strings.TrimSpace(request.Provider)
	if request.ClusterID == "" || request.NodeName == "" || request.Provider == "" {
		return ChallengeRequest{}, fmt.Errorf(
			"%w: cluster_id, node_name, and provider are required",
			ErrInvalid,
		)
	}
	return request, nil
}

// NormalizeChallenge validates and clones a broker challenge.
func NormalizeChallenge(challenge Challenge) (Challenge, error) {
	challenge.ID = strings.TrimSpace(challenge.ID)
	challenge.Nonce = slices.Clone(challenge.Nonce)
	if challenge.ID == "" || len(challenge.Nonce) == 0 || challenge.ExpiresAt.IsZero() {
		return Challenge{}, fmt.Errorf("%w: challenge id, nonce, and expiry are required", ErrInvalid)
	}
	return challenge, nil
}

// NormalizeSubmission validates and clones an untrusted evidence submission.
func NormalizeSubmission(submission Submission) (Submission, error) {
	submission.ClusterID = strings.TrimSpace(submission.ClusterID)
	submission.NodeName = strings.TrimSpace(submission.NodeName)
	submission.NodeUID = strings.TrimSpace(submission.NodeUID)
	submission.Provider = strings.TrimSpace(submission.Provider)
	submission.Format = strings.TrimSpace(submission.Format)
	submission.ChallengeID = strings.TrimSpace(submission.ChallengeID)
	submission.Payload = slices.Clone(submission.Payload)
	if submission.ClusterID == "" || submission.NodeName == "" || submission.Provider == "" {
		return Submission{}, fmt.Errorf(
			"%w: cluster_id, node_name, and provider are required",
			ErrInvalid,
		)
	}
	if submission.Format == "" || len(submission.Payload) == 0 || submission.ChallengeID == "" {
		return Submission{}, fmt.Errorf(
			"%w: format, payload, and challenge_id are required",
			ErrInvalid,
		)
	}
	if submission.RequestedTTL <= 0 {
		return Submission{}, fmt.Errorf("%w: requested_ttl must be greater than zero", ErrInvalid)
	}
	return submission, nil
}

// FakeLocalPayload returns deterministic challenge-bound synthetic evidence.
func FakeLocalPayload(request ChallengeRequest, challenge Challenge) ([]byte, error) {
	request, err := NormalizeChallengeRequest(request)
	if err != nil {
		return nil, err
	}
	challenge.ID = strings.TrimSpace(challenge.ID)
	if challenge.ID == "" || len(challenge.Nonce) == 0 {
		return nil, fmt.Errorf("%w: challenge id and nonce are required", ErrInvalid)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		request.ClusterID,
		request.NodeName,
		request.NodeUID,
		request.Provider,
		challenge.ID,
		string(challenge.Nonce),
	}, "\x00")))
	return sum[:], nil
}
