package broker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
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
	if got.GetNodeUid() != fixtureNodeUID || got.GetStatus() != protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_FRESH {
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

func TestAdminServiceAuditsNodeEvidencePublishAndList(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	now := time.Unix(1_800_000_000, 0).UTC()
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 store,
		policyID:                     config.Policy(),
		allowFakeNodeEvidencePublish: true,
		nodeEvidenceRetention:        DefaultKubernetesNodeEvidenceRetention,
		auditStore:                   store,
		audit:                        NewFileAuditSink(config.AuditFilePath, false),
	})
	service.clock = func() time.Time { return now }

	missing, err := service.ListNodeEvidence(context.Background(), &protocolv1.NodeEvidenceListRequest{
		ClusterId: config.ClusterID,
		NodeName:  testNodeName,
	})
	if err != nil {
		t.Fatalf("missing ListNodeEvidence returned error: %v", err)
	}
	if missing.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("missing list decision = %s, want deny", missing.GetDecision().GetState())
	}

	publish, err := service.PublishNodeEvidence(context.Background(), &protocolv1.NodeEvidencePublishRequest{
		Evidence: testNodeEvidenceRecord(now, now.Add(time.Minute)),
	})
	if err != nil {
		t.Fatalf("PublishNodeEvidence returned error: %v", err)
	}
	if publish.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("publish decision = %s, want allow", publish.GetDecision().GetState())
	}
	list, err := service.ListNodeEvidence(context.Background(), &protocolv1.NodeEvidenceListRequest{
		ClusterId: config.ClusterID,
		NodeName:  testNodeName,
	})
	if err != nil {
		t.Fatalf("ListNodeEvidence returned error: %v", err)
	}
	if list.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("list decision = %s, want allow", list.GetDecision().GetState())
	}

	stored, err := store.AuditEvents(context.Background())
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	assertNodeEvidenceAuditEvent(
		t,
		stored,
		adminOperationNodeEvidenceList,
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
		"",
	)
	assertNodeEvidenceAuditEvent(
		t,
		stored,
		adminOperationNodeEvidencePublish,
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
		"test-node-evidence-hash",
	)
	assertNodeEvidenceAuditEvent(
		t,
		stored,
		adminOperationNodeEvidenceList,
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
		"",
	)

	fileEvents := readAuditEvents(t, config.AuditFilePath)
	if len(fileEvents) != len(stored) {
		t.Fatalf("file audit events = %d, stored audit events = %d", len(fileEvents), len(stored))
	}
	assertNodeEvidenceAuditEvent(
		t,
		fileEvents,
		adminOperationNodeEvidencePublish,
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
		"test-node-evidence-hash",
	)
}

func TestAdminServiceRedactsNodeEvidenceDiagnosticPayloads(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	now := time.Unix(1_800_000_000, 0).UTC()
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 store,
		policyID:                     config.Policy(),
		allowFakeNodeEvidencePublish: true,
		nodeEvidenceRetention:        DefaultKubernetesNodeEvidenceRetention,
		auditStore:                   store,
		audit:                        NewFileAuditSink(config.AuditFilePath, false),
	})
	service.clock = func() time.Time { return now }
	rawClaimValue := "raw-claim-value-do-not-return"
	rawErrorMessage := "raw-error-message-do-not-return"
	rawPolicyID := "raw-policy-id-do-not-return"
	record := testNodeEvidenceRecord(now, now.Add(time.Minute))
	record.PolicyId = rawPolicyID
	record.Claims = []*protocolv1.Claim{{
		Namespace: "kubernetes",
		Name:      "raw-claim",
		Value:     rawClaimValue,
	}}
	record.Errors = []*protocolv1.BrokerError{{
		Code:    protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
		Message: rawErrorMessage,
	}}

	publish, err := service.PublishNodeEvidence(context.Background(), &protocolv1.NodeEvidencePublishRequest{
		Evidence: record,
	})
	if err != nil {
		t.Fatalf("PublishNodeEvidence returned error: %v", err)
	}
	assertRedactedNodeEvidenceRecord(t, publish.GetEvidence())

	list, err := service.ListNodeEvidence(context.Background(), &protocolv1.NodeEvidenceListRequest{
		ClusterId: config.ClusterID,
		NodeName:  testNodeName,
	})
	if err != nil {
		t.Fatalf("ListNodeEvidence returned error: %v", err)
	}
	if len(list.GetEvidence()) != 1 {
		t.Fatalf("listed evidence = %d, want 1", len(list.GetEvidence()))
	}
	assertRedactedNodeEvidenceRecord(t, list.GetEvidence()[0])

	auditFile := readAuditFile(t, config.AuditFilePath)
	for _, raw := range []string{rawClaimValue, rawErrorMessage, rawPolicyID} {
		if strings.Contains(auditFile, raw) {
			t.Fatalf("audit file contains redacted node evidence payload %q: %s", raw, auditFile)
		}
	}
}

func TestAdminServiceCheckEvidenceAllowsKubernetesWorkload(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := store.InsertSubject(context.Background(), config.ClusterID, testKubernetesSubject, now); err != nil {
		t.Fatalf("InsertSubject returned error: %v", err)
	}
	putTestNodeEvidence(t, store, config, fixtureNodeUID, now, now.Add(time.Minute))
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 store,
		policyID:                     config.Policy(),
		allowFakeNodeEvidencePublish: true,
		nodeEvidenceRetention:        DefaultKubernetesNodeEvidenceRetention,
		auditStore:                   store,
		audit:                        NewFileAuditSink(config.AuditFilePath, false),
		store:                        store,
		verifier: testKubernetesEvidenceVerifier(
			testKubernetesTokenReviewStatus(),
		),
	})
	service.clock = func() time.Time { return now }
	evidence, err := k8sprovider.NewEvidenceEnvelope("", "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}

	resp, err := service.CheckEvidence(context.Background(), &protocolv1.EvidenceCheckRequest{
		ClusterId: config.ClusterID,
		Operation: protocolv1.Operation_OPERATION_WRAP,
		Evidence:  evidence,
	})
	if err != nil {
		t.Fatalf("CheckEvidence returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("check decision = %s, want allow", resp.GetDecision().GetState())
	}
	if resp.GetSubject() != testKubernetesSubject {
		t.Fatalf("subject = %q, want %s", resp.GetSubject(), testKubernetesSubject)
	}
	if resp.GetWorkload().GetNodeName() != testNodeName ||
		resp.GetNodeEvidence().GetStatus() != protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_FRESH {
		t.Fatalf("workload/evidence = %#v/%#v, want node evidence match", resp.GetWorkload(), resp.GetNodeEvidence())
	}
	assertNodeEvidencePayloadRedacted(t, resp.GetNodeEvidence())
}

func TestAdminServiceCheckEvidenceReportsRejectedAudience(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	status := testKubernetesTokenReviewStatus()
	status.Audiences = []string{"wrong-audience"}
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 store,
		policyID:                     config.Policy(),
		allowFakeNodeEvidencePublish: true,
		nodeEvidenceRetention:        DefaultKubernetesNodeEvidenceRetention,
		store:                        store,
		verifier:                     testKubernetesEvidenceVerifier(status),
	})
	evidence, err := k8sprovider.NewEvidenceEnvelope("", "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}

	resp, err := service.CheckEvidence(context.Background(), &protocolv1.EvidenceCheckRequest{
		ClusterId: config.ClusterID,
		Operation: protocolv1.Operation_OPERATION_WRAP,
		Evidence:  evidence,
	})
	if err != nil {
		t.Fatalf("CheckEvidence returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("check decision = %s, want deny", resp.GetDecision().GetState())
	}
	if len(resp.GetDecision().GetErrors()) != 1 ||
		resp.GetDecision().GetErrors()[0].GetCode() != protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED ||
		resp.GetDecision().GetErrors()[0].GetMessage() != "kubernetes token audience was not accepted" {
		t.Fatalf("check errors = %#v, want audience denial", resp.GetDecision().GetErrors())
	}
	if resp.GetWorkload() != nil || resp.GetNodeEvidence() != nil {
		t.Fatalf("diagnostic response leaked workload/evidence on invalid token: %#v", resp)
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

func TestAdminServicePrunesNodeEvidenceBeforeList(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	cache := NewMemoryNodeEvidenceCache()
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 cache,
		policyID:                     "development",
		allowFakeNodeEvidencePublish: true,
		nodeEvidenceRetention:        time.Hour,
	})
	service.clock = func() time.Time { return now }

	old := NodeEvidence{
		ClusterID:    "prod-eu1",
		NodeName:     "node-old",
		NodeUID:      "old-node-uid",
		Provider:     NodeEvidenceProviderFakeLocal,
		EvidenceHash: "old-node-evidence-hash",
		CollectedAt:  now.Add(-3 * time.Hour),
		ExpiresAt:    now.Add(-2 * time.Hour),
	}
	if err := cache.PutNodeEvidence(context.Background(), old); err != nil {
		t.Fatalf("PutNodeEvidence old returned error: %v", err)
	}
	recent := NodeEvidence{
		ClusterID:    "prod-eu1",
		NodeName:     testNodeName,
		NodeUID:      fixtureNodeUID,
		Provider:     NodeEvidenceProviderFakeLocal,
		EvidenceHash: "recent-node-evidence-hash",
		CollectedAt:  now.Add(-45 * time.Minute),
		ExpiresAt:    now.Add(-30 * time.Minute),
	}
	if err := cache.PutNodeEvidence(context.Background(), recent); err != nil {
		t.Fatalf("PutNodeEvidence recent returned error: %v", err)
	}

	list, err := service.ListNodeEvidence(context.Background(), &protocolv1.NodeEvidenceListRequest{
		ClusterId: "prod-eu1",
	})
	if err != nil {
		t.Fatalf("ListNodeEvidence returned error: %v", err)
	}
	if list.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("list decision = %s, want allow", list.GetDecision().GetState())
	}
	if len(list.GetEvidence()) != 1 || list.GetEvidence()[0].GetNodeName() != testNodeName {
		t.Fatalf("list evidence = %#v, want only %s", list.GetEvidence(), testNodeName)
	}
	_, err = cache.NodeEvidence(context.Background(), "prod-eu1", "node-old")
	if !errors.Is(err, ErrNodeEvidenceNotFound) {
		t.Fatalf("old node evidence error = %v, want ErrNodeEvidenceNotFound", err)
	}
}

func assertNodeEvidenceAuditEvent(
	t *testing.T,
	events []AuditEvent,
	operation string,
	decision protocolv1.PolicyDecisionState,
	evidenceHash string,
) {
	t.Helper()
	for _, event := range events {
		if event.Operation != operation || event.Decision != decision.String() {
			continue
		}
		if event.ClusterID != "prod-eu1" || event.PolicyID != "development" {
			t.Fatalf("audit event = %#v, want prod-eu1 development", event)
		}
		if event.Subject != "" && event.Subject != testNodeName {
			t.Fatalf("audit subject = %q, want empty or %s", event.Subject, testNodeName)
		}
		if evidenceHash != "" && event.EvidenceHash != evidenceHash {
			t.Fatalf("audit evidence hash = %q, want %s", event.EvidenceHash, evidenceHash)
		}
		return
	}
	t.Fatalf("missing audit event operation=%s decision=%s in %#v", operation, decision, events)
}

func assertRedactedNodeEvidenceRecord(t *testing.T, record *protocolv1.NodeEvidenceRecord) {
	t.Helper()
	if record == nil {
		t.Fatal("node evidence record is nil")
	}
	if record.GetPolicyId() != "" {
		t.Fatalf("node evidence policy_id = %q, want empty", record.GetPolicyId())
	}
	if len(record.GetClaims()) != 0 {
		t.Fatalf("node evidence claims = %#v, want none", record.GetClaims())
	}
	if len(record.GetErrors()) != 0 {
		t.Fatalf("node evidence errors = %#v, want none", record.GetErrors())
	}
	if record.GetClusterId() != "prod-eu1" ||
		record.GetNodeName() != testNodeName ||
		record.GetNodeUid() != fixtureNodeUID ||
		record.GetProviderId() != NodeEvidenceProviderFakeLocal ||
		record.GetEvidenceHash() != "test-node-evidence-hash" {
		t.Fatalf("node evidence metadata = %#v, want diagnostic metadata preserved", record)
	}
}

func assertNodeEvidencePayloadRedacted(t *testing.T, record *protocolv1.NodeEvidenceRecord) {
	t.Helper()
	if record == nil {
		t.Fatal("node evidence record is nil")
	}
	if record.GetPolicyId() != "" {
		t.Fatalf("node evidence policy_id = %q, want empty", record.GetPolicyId())
	}
	if len(record.GetClaims()) != 0 {
		t.Fatalf("node evidence claims = %#v, want none", record.GetClaims())
	}
	if len(record.GetErrors()) != 0 {
		t.Fatalf("node evidence errors = %#v, want none", record.GetErrors())
	}
}

func testNodeEvidenceRecord(collectedAt time.Time, expiresAt time.Time) *protocolv1.NodeEvidenceRecord {
	return &protocolv1.NodeEvidenceRecord{
		ClusterId:            "prod-eu1",
		NodeName:             "node-a",
		NodeUid:              fixtureNodeUID,
		ProviderId:           "fake-local",
		EvidenceHash:         "test-node-evidence-hash",
		CollectedUnixSeconds: collectedAt.Unix(),
		ExpiresUnixSeconds:   expiresAt.Unix(),
	}
}
