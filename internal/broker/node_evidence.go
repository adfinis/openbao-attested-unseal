package broker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNodeEvidenceNotFound indicates that no node evidence is cached for a workload node.
	ErrNodeEvidenceNotFound = errors.New("node evidence not found")
	// ErrNodeEvidenceStale indicates that cached node evidence is no longer fresh enough for policy.
	ErrNodeEvidenceStale = errors.New("node evidence stale")
	// ErrNodeEvidenceInvalid indicates that a node evidence record is incomplete or malformed.
	ErrNodeEvidenceInvalid = errors.New("node evidence invalid")
)

// NodeEvidence records broker-trusted evidence for one Kubernetes node.
type NodeEvidence struct {
	ClusterID    string
	NodeName     string
	NodeUID      string
	Provider     string
	EvidenceHash string
	CollectedAt  time.Time
	ExpiresAt    time.Time
}

// NodeEvidenceReader returns fresh node evidence for workload-to-node correlation.
type NodeEvidenceReader interface {
	FreshNodeEvidence(ctx context.Context, clusterID string, nodeName string, now time.Time) (NodeEvidence, error)
}

// NodeEvidenceWriter stores node evidence collected by a node evidence publisher.
type NodeEvidenceWriter interface {
	PutNodeEvidence(ctx context.Context, evidence NodeEvidence) error
}

// MemoryNodeEvidenceCache is a process-local node evidence cache.
type MemoryNodeEvidenceCache struct {
	mu      sync.RWMutex
	records map[nodeEvidenceKey]NodeEvidence
}

type nodeEvidenceKey struct {
	clusterID string
	nodeName  string
}

// NewMemoryNodeEvidenceCache creates an empty process-local node evidence cache.
func NewMemoryNodeEvidenceCache() *MemoryNodeEvidenceCache {
	return &MemoryNodeEvidenceCache{
		records: make(map[nodeEvidenceKey]NodeEvidence),
	}
}

// PutNodeEvidence stores or replaces cached node evidence.
func (c *MemoryNodeEvidenceCache) PutNodeEvidence(_ context.Context, evidence NodeEvidence) error {
	if c == nil {
		return fmt.Errorf("%w: cache is nil", ErrNodeEvidenceInvalid)
	}
	normalized, err := normalizeNodeEvidence(evidence)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[nodeEvidenceKey{
		clusterID: normalized.ClusterID,
		nodeName:  normalized.NodeName,
	}] = normalized
	return nil
}

// FreshNodeEvidence returns cached node evidence if it exists and has not expired.
func (c *MemoryNodeEvidenceCache) FreshNodeEvidence(
	_ context.Context,
	clusterID string,
	nodeName string,
	now time.Time,
) (NodeEvidence, error) {
	if c == nil {
		return NodeEvidence{}, ErrNodeEvidenceNotFound
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := nodeEvidenceKey{
		clusterID: strings.TrimSpace(clusterID),
		nodeName:  strings.TrimSpace(nodeName),
	}
	c.mu.RLock()
	evidence, ok := c.records[key]
	c.mu.RUnlock()
	if !ok {
		return NodeEvidence{}, ErrNodeEvidenceNotFound
	}
	if !evidence.ExpiresAt.After(now) {
		return evidence, ErrNodeEvidenceStale
	}
	return evidence, nil
}

func normalizeNodeEvidence(evidence NodeEvidence) (NodeEvidence, error) {
	evidence.ClusterID = strings.TrimSpace(evidence.ClusterID)
	evidence.NodeName = strings.TrimSpace(evidence.NodeName)
	evidence.NodeUID = strings.TrimSpace(evidence.NodeUID)
	evidence.Provider = strings.TrimSpace(evidence.Provider)
	evidence.EvidenceHash = strings.TrimSpace(evidence.EvidenceHash)
	if evidence.ClusterID == "" || evidence.NodeName == "" {
		return NodeEvidence{}, fmt.Errorf("%w: cluster_id and node_name are required", ErrNodeEvidenceInvalid)
	}
	if evidence.CollectedAt.IsZero() || evidence.ExpiresAt.IsZero() {
		return NodeEvidence{}, fmt.Errorf("%w: collected_at and expires_at are required", ErrNodeEvidenceInvalid)
	}
	if !evidence.ExpiresAt.After(evidence.CollectedAt) {
		return NodeEvidence{}, fmt.Errorf("%w: expires_at must be after collected_at", ErrNodeEvidenceInvalid)
	}
	return evidence, nil
}
