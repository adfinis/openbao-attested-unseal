package broker

import (
	"context"
	"testing"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

func TestAdminServicePublishesAndListsNodeEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	cache := NewMemoryNodeEvidenceCache()
	service := NewAdminService(cache, "development", true)
	service.clock = func() time.Time { return now }

	publish, err := service.PublishNodeEvidence(context.Background(), &protocolv1.NodeEvidencePublishRequest{
		Evidence: testNodeEvidenceRecord(now, now.Add(time.Minute)),
	})
	if err != nil {
		t.Fatalf("PublishNodeEvidence returned error: %v", err)
	}
	if publish.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("publish decision = %s, want allow", publish.GetDecision().GetState())
	}
	if publish.GetEvidence().GetProviderId() != "fake-local" {
		t.Fatalf("published provider_id = %q, want fake-local", publish.GetEvidence().GetProviderId())
	}

	list, err := service.ListNodeEvidence(context.Background(), &protocolv1.NodeEvidenceListRequest{
		ClusterId: "prod-eu1",
		NodeName:  "node-a",
	})
	if err != nil {
		t.Fatalf("ListNodeEvidence returned error: %v", err)
	}
	if list.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("list decision = %s, want allow", list.GetDecision().GetState())
	}
	if len(list.GetEvidence()) != 1 {
		t.Fatalf("list evidence count = %d, want 1", len(list.GetEvidence()))
	}
	got := list.GetEvidence()[0]
	if got.GetNodeUid() != "node-uid" || got.GetStatus() != protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_FRESH {
		t.Fatalf("listed evidence = %+v, want node-uid fresh", got)
	}
}

func TestAdminServiceReportsStaleNodeEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	cache := NewMemoryNodeEvidenceCache()
	service := NewAdminService(cache, "development", true)
	service.clock = func() time.Time { return now }

	publish, err := service.PublishNodeEvidence(context.Background(), &protocolv1.NodeEvidencePublishRequest{
		Evidence: testNodeEvidenceRecord(now.Add(-2*time.Minute), now.Add(-time.Minute)),
	})
	if err != nil {
		t.Fatalf("PublishNodeEvidence returned error: %v", err)
	}
	if publish.GetEvidence().GetStatus() != protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_STALE {
		t.Fatalf("published status = %s, want stale", publish.GetEvidence().GetStatus())
	}
}

func TestAdminServiceRejectsInvalidNodeEvidence(t *testing.T) {
	service := NewAdminService(NewMemoryNodeEvidenceCache(), "development", true)
	tests := map[string]*protocolv1.NodeEvidencePublishRequest{
		"nil request": nil,
		"empty record": {
			Evidence: &protocolv1.NodeEvidenceRecord{ClusterId: "prod-eu1"},
		},
		"missing timestamps": {
			Evidence: &protocolv1.NodeEvidenceRecord{
				ClusterId:    "prod-eu1",
				NodeName:     "node-a",
				ProviderId:   "fake-local",
				EvidenceHash: "test-node-evidence-hash",
			},
		},
	}
	for name, req := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := service.PublishNodeEvidence(context.Background(), req)
			if err != nil {
				t.Fatalf("PublishNodeEvidence returned error: %v", err)
			}
			if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
				t.Fatalf("publish decision = %s, want deny", resp.GetDecision().GetState())
			}
		})
	}
}

func TestAdminServiceRejectsFakePublishWhenDisabled(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	service := NewAdminService(NewMemoryNodeEvidenceCache(), "development", false)

	resp, err := service.PublishNodeEvidence(context.Background(), &protocolv1.NodeEvidencePublishRequest{
		Evidence: testNodeEvidenceRecord(now, now.Add(time.Minute)),
	})
	if err != nil {
		t.Fatalf("PublishNodeEvidence returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("publish decision = %s, want deny", resp.GetDecision().GetState())
	}
	if got := resp.GetDecision().GetErrors()[0].GetCode(); got != protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("publish error code = %s, want permission denied", got)
	}
}

func testNodeEvidenceRecord(collectedAt time.Time, expiresAt time.Time) *protocolv1.NodeEvidenceRecord {
	return &protocolv1.NodeEvidenceRecord{
		ClusterId:            "prod-eu1",
		NodeName:             "node-a",
		NodeUid:              "node-uid",
		ProviderId:           "fake-local",
		EvidenceHash:         "test-node-evidence-hash",
		CollectedUnixSeconds: collectedAt.Unix(),
		ExpiresUnixSeconds:   expiresAt.Unix(),
	}
}
