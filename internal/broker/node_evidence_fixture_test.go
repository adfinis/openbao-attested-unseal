package broker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
	fixtureClusterID = "prod-eu1"
	fixtureNodeName  = "node-a"
	fixtureNodeUID   = "node-uid"
	fixtureProvider  = "fake-local"
)

func TestKubernetesNodeEvidenceFixturesDrivePolicy(t *testing.T) {
	now := fixtureTime(t, "2026-06-29T20:01:00Z")
	tests := []struct {
		name       string
		fixture    string
		wantState  protocolv1.PolicyDecisionState
		wantCode   protocolv1.ErrorCode
		wantReason string
	}{
		{
			name:       "fresh evidence allows",
			fixture:    "fake-local-fresh.json",
			wantState:  protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
			wantReason: "allowed by development subject policy",
		},
		{
			name:       "stale evidence denies",
			fixture:    "fake-local-stale.json",
			wantState:  protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
			wantCode:   protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
			wantReason: "node evidence is stale",
		},
		{
			name:       "node UID mismatch denies",
			fixture:    "fake-local-node-uid-mismatch.json",
			wantState:  protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
			wantCode:   protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
			wantReason: "node evidence does not match workload node",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewMemoryNodeEvidenceCache()
			evidence := loadNodeEvidenceFixture(t, tt.fixture)
			if evidence.Provider != fixtureProvider {
				t.Fatalf("fixture provider = %q, want %s", evidence.Provider, fixtureProvider)
			}
			if err := cache.PutNodeEvidence(context.Background(), evidence); err != nil {
				t.Fatalf("PutNodeEvidence returned error: %v", err)
			}
			engine := &PolicyEngine{
				nodeEvidence: cache,
				policyID:     DevelopmentProfile,
				clock:        func() time.Time { return now },
			}
			decision := engine.evaluateNodeEvidence(context.Background(), policyRequest{
				ClusterID: fixtureClusterID,
				Workload: WorkloadIdentity{
					NodeName: fixtureNodeName,
					NodeUID:  fixtureNodeUID,
				},
			})
			if decision.State != tt.wantState || decision.ErrorCode != tt.wantCode || decision.Reason != tt.wantReason {
				t.Fatalf(
					"decision = %s/%s/%q, want %s/%s/%q",
					decision.State,
					decision.ErrorCode,
					decision.Reason,
					tt.wantState,
					tt.wantCode,
					tt.wantReason,
				)
			}
		})
	}
}

type nodeEvidenceFixture struct {
	ClusterID    string `json:"cluster_id"`
	NodeName     string `json:"node_name"`
	NodeUID      string `json:"node_uid"`
	Provider     string `json:"provider"`
	EvidenceHash string `json:"evidence_hash"`
	CollectedAt  string `json:"collected_at"`
	ExpiresAt    string `json:"expires_at"`
}

func loadNodeEvidenceFixture(t *testing.T, name string) NodeEvidence {
	t.Helper()
	path := filepath.Join("testdata", "kubernetes-node-evidence", name)
	// #nosec G304 -- test fixture names are controlled by the static test table.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) returned error: %v", path, err)
	}
	var fixture nodeEvidenceFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("Unmarshal(%s) returned error: %v", path, err)
	}
	return NodeEvidence{
		ClusterID:    fixture.ClusterID,
		NodeName:     fixture.NodeName,
		NodeUID:      fixture.NodeUID,
		Provider:     fixture.Provider,
		EvidenceHash: fixture.EvidenceHash,
		CollectedAt:  fixtureTime(t, fixture.CollectedAt),
		ExpiresAt:    fixtureTime(t, fixture.ExpiresAt),
	}
}

func fixtureTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("Parse(%q) returned error: %v", value, err)
	}
	return parsed
}
