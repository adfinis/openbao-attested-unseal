package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

func TestEnrollmentServiceRunsThroughMutualTLSControlPlane(t *testing.T) {
	config := testConfig(t)
	pki := newTestPKI(t)
	config.AllowPlaintextForTests = false
	config.TLSCertFile = pki.serverCert
	config.TLSKeyFile = pki.serverKey
	config.ClientCAFile = pki.caCert
	config.RequireClientCert = true
	config.ControlPlane.Identities = map[string]ControlPlaneIdentity{
		certificateFileSHA256(t, pki.clientCert): {
			Roles:      []string{ControlPlaneRoleNodeEvidenceAdmin},
			ClusterIDs: []string{config.ClusterID},
		},
	}
	runtime := newTestRuntime(t, config)
	listener := startRuntimeOnListener(t, runtime)
	conn := dialTLS(t, listener.Addr().String(), pki.caCert, "localhost", pki.clientCert, pki.clientKey)
	defer func() { _ = conn.Close() }()

	response, err := protocolv1.NewEnrollmentServiceClient(conn).EnrollNodeEvidence(
		context.Background(),
		&protocolv1.NodeEvidenceEnrollmentRequest{
			ClusterId:  config.ClusterID,
			NodeName:   testNodeName,
			NodeUid:    fixtureNodeUID,
			ProviderId: nodeevidence.ProviderTPM2Quote,
			TpmPolicy: &protocolv1.NodeEvidenceTPMPolicy{
				Mode:                 tpmlocal.PolicyModeTPMOnly,
				EnrolledAkPublicHash: "sha256:" + strings.Repeat("cd", 32),
			},
			PublisherCertificateSha256: []string{"sha256:" + strings.Repeat("ab", 32)},
			Reason:                     "mTLS integration enrollment",
		},
	)
	if err != nil {
		t.Fatalf("EnrollNodeEvidence RPC returned error: %v", err)
	}
	if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW ||
		response.GetEnrollment().GetRevision() != 1 {
		t.Fatalf("EnrollNodeEvidence RPC response = %#v, want revision 1 allow", response)
	}
}

func TestSQLiteMigrationInvalidatesPreEnrollmentTPMEvidence(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	store := newTestStore(t, config)
	now := time.Date(2026, time.August, 12, 9, 0, 0, 0, time.UTC)
	if err := store.PutNodeEvidence(context.Background(), NodeEvidence{
		ClusterID:    config.ClusterID,
		NodeName:     testNodeName,
		NodeUID:      fixtureNodeUID,
		Provider:     nodeevidence.ProviderTPM2Quote,
		EvidenceHash: "sha256:" + strings.Repeat("ef", 32),
		CollectedAt:  now,
		ExpiresAt:    now.Add(time.Minute),
	}); !errors.Is(err, nodeevidence.ErrEnrollmentChanged) {
		t.Fatalf("unenrolled TPM evidence write error = %v, want ErrEnrollmentChanged", err)
	}
	_, err := store.db.ExecContext(
		context.Background(),
		`INSERT INTO node_evidence(
		   cluster_id, node_name, node_uid, provider, evidence_hash, collected_at,
		   expires_at, updated_at, enrollment_revision
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		config.ClusterID,
		testNodeName,
		fixtureNodeUID,
		nodeevidence.ProviderTPM2Quote,
		"sha256:"+strings.Repeat("ef", 32),
		now.Format(time.RFC3339Nano),
		now.Add(time.Minute).Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("seed pre-enrollment TPM evidence: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close seeded store: %v", err)
	}
	reopened, err := OpenSQLiteStore(context.Background(), config.SQLitePath)
	if err != nil {
		t.Fatalf("reopen migrated store: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.NodeEvidence(context.Background(), config.ClusterID, testNodeName); !errors.Is(
		err,
		ErrNodeEvidenceNotFound,
	) {
		t.Fatalf("pre-enrollment TPM evidence after migration error = %v, want not found", err)
	}
}

//nolint:gocyclo // One lifecycle test preserves the state-transition narrative.
func TestEnrollmentServiceOwnsRevisionedNodeTrustLifecycle(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	store := newTestStore(t, config)
	operatorCtx := nodeEvidencePublisherTestContext(t, []byte("node-enrollment-operator"))
	operatorHash, err := nodeEvidenceClientCertificateHash(operatorCtx)
	if err != nil {
		t.Fatalf("operator certificate hash: %v", err)
	}
	publisherHash := "sha256:" + strings.Repeat("ab", 32)
	now := time.Date(2026, time.August, 12, 10, 0, 0, 0, time.UTC)
	service := newEnrollmentService(enrollmentServiceConfig{
		store:      store,
		auditStore: store,
		identities: map[string]ControlPlaneIdentity{
			operatorHash: {
				Roles:      []string{ControlPlaneRoleNodeEvidenceAdmin},
				ClusterIDs: []string{config.ClusterID},
			},
		},
		clusterID: config.ClusterID,
		policyID:  config.Policy(),
	})
	service.clock = func() time.Time { return now }

	request := &protocolv1.NodeEvidenceEnrollmentRequest{
		ClusterId:  config.ClusterID,
		NodeName:   testNodeName,
		NodeUid:    fixtureNodeUID,
		ProviderId: nodeevidence.ProviderTPM2Quote,
		TpmPolicy: &protocolv1.NodeEvidenceTPMPolicy{
			Mode:                 tpmlocal.PolicyModeTPMOnly,
			EnrolledAkPublicHash: "sha256:" + strings.Repeat("cd", 32),
		},
		PublisherCertificateSha256: []string{publisherHash},
		Reason:                     "approve node replacement CHG-1234",
		Audit: &protocolv1.AuditContext{
			CorrelationId: "corr-node-enroll",
			RequestId:     "request-node-enroll",
		},
	}
	response, err := service.EnrollNodeEvidence(operatorCtx, request)
	if err != nil {
		t.Fatalf("EnrollNodeEvidence returned error: %v", err)
	}
	if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("enrollment decision = %#v, want allow", response.GetDecision())
	}
	if response.GetEnrollment().GetRevision() != 1 {
		t.Fatalf("enrollment revision = %d, want 1", response.GetEnrollment().GetRevision())
	}
	first, err := store.ActiveNodeEvidenceEnrollment(context.Background(), config.ClusterID, testNodeName)
	if err != nil {
		t.Fatalf("ActiveNodeEvidenceEnrollment returned error: %v", err)
	}
	evidence := NodeEvidence{
		ClusterID:    config.ClusterID,
		NodeName:     testNodeName,
		NodeUID:      fixtureNodeUID,
		Provider:     nodeevidence.ProviderTPM2Quote,
		EvidenceHash: "sha256:" + strings.Repeat("ef", 32),
		CollectedAt:  now,
		ExpiresAt:    now.Add(time.Minute),
	}
	if err := store.PutEnrolledNodeEvidence(context.Background(), evidence, first.Revision); err != nil {
		t.Fatalf("PutEnrolledNodeEvidence returned error: %v", err)
	}

	service.clock = func() time.Time { return now.Add(time.Minute) }
	request.Reason = "rotate publisher authorization CHG-1235"
	reenrolled, err := service.EnrollNodeEvidence(operatorCtx, request)
	if err != nil {
		t.Fatalf("re-enroll returned error: %v", err)
	}
	if reenrolled.GetEnrollment().GetRevision() != 2 {
		t.Fatalf("re-enrollment revision = %d, want 2", reenrolled.GetEnrollment().GetRevision())
	}
	if _, err := store.NodeEvidence(context.Background(), config.ClusterID, testNodeName); !errors.Is(
		err,
		ErrNodeEvidenceNotFound,
	) {
		t.Fatalf("node evidence after re-enrollment error = %v, want not found", err)
	}
	if err := store.PutEnrolledNodeEvidence(context.Background(), evidence, first.Revision); !errors.Is(
		err,
		nodeevidence.ErrEnrollmentChanged,
	) {
		t.Fatalf("stale revision write error = %v, want ErrEnrollmentChanged", err)
	}

	events, err := store.AuditEvents(context.Background())
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("audit event count = %d, want 2", len(events))
	}
	if events[0].Actor != operatorHash || events[0].Target != testNodeName ||
		events[0].CorrelationID != "corr-node-enroll" || events[0].RequestID != "request-node-enroll" {
		t.Fatalf("enrollment audit identity/context = %#v", events[0])
	}
	if events[0].Reason != "approve node replacement CHG-1234" {
		t.Fatalf("enrollment audit reason = %q", events[0].Reason)
	}
}

func TestEnrollmentServiceRevocationInvalidatesEvidenceImmediately(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	store := newTestStore(t, config)
	operatorCtx := nodeEvidencePublisherTestContext(t, []byte("node-revocation-operator"))
	operatorHash, err := nodeEvidenceClientCertificateHash(operatorCtx)
	if err != nil {
		t.Fatalf("operator certificate hash: %v", err)
	}
	now := time.Date(2026, time.August, 12, 11, 0, 0, 0, time.UTC)
	service := newEnrollmentService(enrollmentServiceConfig{
		store:      store,
		auditStore: store,
		identities: map[string]ControlPlaneIdentity{
			operatorHash: {
				Roles:      []string{ControlPlaneRoleNodeEvidenceAdmin},
				ClusterIDs: []string{config.ClusterID},
			},
		},
		clusterID: config.ClusterID,
		policyID:  config.Policy(),
	})
	service.clock = func() time.Time { return now }
	enrollment, err := store.EnrollNodeEvidence(context.Background(), nodeevidence.EnrollmentRequest{
		ClusterID: config.ClusterID,
		NodeName:  testNodeName,
		NodeUID:   fixtureNodeUID,
		Provider:  nodeevidence.ProviderTPM2Quote,
		TPMPolicy: tpmlocal.Policy{
			Mode:                 tpmlocal.PolicyModeTPMOnly,
			EnrolledAKPublicHash: "sha256:" + strings.Repeat("cd", 32),
		},
		PublisherCertificateHashes: []string{"sha256:" + strings.Repeat("ab", 32)},
		EnrolledAt:                 now,
	})
	if err != nil {
		t.Fatalf("seed enrollment: %v", err)
	}
	if err := store.PutEnrolledNodeEvidence(context.Background(), NodeEvidence{
		ClusterID:    config.ClusterID,
		NodeName:     testNodeName,
		NodeUID:      fixtureNodeUID,
		Provider:     nodeevidence.ProviderTPM2Quote,
		EvidenceHash: "sha256:" + strings.Repeat("ef", 32),
		CollectedAt:  now,
		ExpiresAt:    now.Add(time.Minute),
	}, enrollment.Revision); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}

	response, err := service.RevokeNodeEvidence(operatorCtx, &protocolv1.NodeEvidenceRevocationRequest{
		ClusterId: config.ClusterID,
		NodeName:  testNodeName,
		Reason:    "node decommissioned CHG-1236",
	})
	if err != nil {
		t.Fatalf("RevokeNodeEvidence returned error: %v", err)
	}
	if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW ||
		response.GetEnrollment().GetRevokedUnixSeconds() == 0 {
		t.Fatalf("revocation response = %#v, want revoked allow", response)
	}
	if _, err := store.ActiveNodeEvidenceEnrollment(context.Background(), config.ClusterID, testNodeName); !errors.Is(
		err,
		nodeevidence.ErrEnrollmentRevoked,
	) {
		t.Fatalf("active enrollment error = %v, want revoked", err)
	}
	if _, err := store.NodeEvidence(context.Background(), config.ClusterID, testNodeName); !errors.Is(
		err,
		ErrNodeEvidenceNotFound,
	) {
		t.Fatalf("node evidence after revocation error = %v, want not found", err)
	}
}

func TestEnrollmentServiceRejectsUnprivilegedCertificate(t *testing.T) {
	t.Parallel()
	config := testConfig(t)
	store := newTestStore(t, config)
	service := newEnrollmentService(enrollmentServiceConfig{
		store:      store,
		auditStore: store,
		clusterID:  config.ClusterID,
		policyID:   config.Policy(),
	})
	response, err := service.EnrollNodeEvidence(
		nodeEvidencePublisherTestContext(t, []byte("unprivileged-certificate")),
		&protocolv1.NodeEvidenceEnrollmentRequest{
			ClusterId:  config.ClusterID,
			NodeName:   testNodeName,
			NodeUid:    fixtureNodeUID,
			ProviderId: nodeevidence.ProviderTPM2Quote,
			TpmPolicy: &protocolv1.NodeEvidenceTPMPolicy{
				Mode:                 tpmlocal.PolicyModeTPMOnly,
				EnrolledAkPublicHash: "sha256:" + strings.Repeat("cd", 32),
			},
			PublisherCertificateSha256: []string{"sha256:" + strings.Repeat("ab", 32)},
			Reason:                     "should not be accepted",
		},
	)
	if err != nil {
		t.Fatalf("EnrollNodeEvidence returned error: %v", err)
	}
	if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY ||
		response.GetDecision().GetErrors()[0].GetCode() != protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("unprivileged decision = %#v, want permission denied", response.GetDecision())
	}
	if _, err := store.ActiveNodeEvidenceEnrollment(context.Background(), config.ClusterID, testNodeName); !errors.Is(
		err,
		nodeevidence.ErrEnrollmentNotFound,
	) {
		t.Fatalf("unexpected enrollment after denial: %v", err)
	}
}

func certificateFileSHA256(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- test helper reads a generated certificate path.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("decode certificate PEM")
	}
	digest := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}
