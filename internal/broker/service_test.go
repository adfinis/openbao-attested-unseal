package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	testKubernetesSubject = "openbao.openbao"
	testNodeName          = "node-a"
)

func TestSQLiteMigrationIdempotency(t *testing.T) {
	store := newTestStore(t, testConfig(t))
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}
}

func TestChallengeExpiry(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	challenge := testChallenge(t, config)
	challenge.ExpiresAt = time.Now().Add(-time.Second)
	if err := store.CreateChallenge(context.Background(), challenge); err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	err := store.ConsumeChallenge(
		context.Background(),
		challenge.ID,
		config.ClusterID,
		config.DevelopmentSubject,
		protocolv1.Operation_OPERATION_WRAP,
		time.Now(),
	)
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("ConsumeChallenge error = %v, want ErrChallengeExpired", err)
	}
}

func TestBrokerWrapUnwrapRoundTripAndRestartReload(t *testing.T) {
	config := testConfig(t)
	runtime := newTestRuntime(t, config)
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	blob := brokerWrap(t, client, config, config.DevelopmentSubject, []byte("seal plaintext"), []byte("aad"))
	plaintext := brokerUnwrap(t, client, config, config.DevelopmentSubject, blob, []byte("aad"))
	if string(plaintext) != "seal plaintext" {
		t.Fatalf("plaintext = %q, want seal plaintext", plaintext)
	}
	if !hasAuditDecision(
		readAuditEvents(t, config.AuditFilePath),
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
	) {
		t.Fatal("audit file does not contain an allow decision")
	}

	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("runtime close returned error: %v", err)
	}
	reopened, err := OpenSQLiteStore(context.Background(), config.SQLitePath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore returned error: %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := reopened.Subject(context.Background(), config.ClusterID, config.DevelopmentSubject); err != nil {
		t.Fatalf("Subject after restart returned error: %v", err)
	}
	if _, err := reopened.LoadKeyring(context.Background(), config.ClusterID); err != nil {
		t.Fatalf("LoadKeyring after restart returned error: %v", err)
	}
}

func TestDefaultPolicyFileSubjectsAreLoaded(t *testing.T) {
	config := testConfig(t)
	config.PolicyID = ""
	config.DevelopmentSubject = ""
	config.DefaultPolicyPath = writePolicyDocument(t, config, "policy-node")
	runtime := newTestRuntime(t, config)
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	blob := brokerWrap(t, client, config, "policy-node", []byte("seal plaintext"), nil)
	plaintext := brokerUnwrap(t, client, config, "policy-node", blob, nil)
	if string(plaintext) != "seal plaintext" {
		t.Fatalf("plaintext = %q, want seal plaintext", plaintext)
	}
}

func TestDeniedRequestWritesRedactedAuditEvent(t *testing.T) {
	config := testConfig(t)
	runtime := newTestRuntime(t, config)
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	denySubject := "unknown-node"
	challenge, err := client.Challenge(context.Background(), &protocolv1.ChallengeRequest{
		ClusterId: config.ClusterID,
		NodeId:    denySubject,
		Operation: protocolv1.Operation_OPERATION_WRAP,
	})
	if err != nil {
		t.Fatalf("Challenge returned error: %v", err)
	}
	resp, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: []byte("do-not-log"),
		Aad:       []byte("do-not-log-aad"),
		Evidence:  testEvidence(challenge.GetChallengeId(), denySubject),
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("decision = %s, want deny", resp.GetDecision().GetState())
	}

	events, err := runtime.Store.AuditEvents(context.Background())
	if err != nil {
		t.Fatalf("AuditEvents returned error: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no audit events were stored")
	}
	if !hasAuditDecision(
		readAuditEvents(t, config.AuditFilePath),
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
	) {
		t.Fatal("audit file does not contain a deny decision")
	}
	encodedKey := base64.StdEncoding.EncodeToString(testKeyMaterial())
	auditFile := readAuditFile(t, config.AuditFilePath)
	if strings.Contains(auditFile, "do-not-log") || strings.Contains(auditFile, encodedKey) {
		t.Fatalf("audit file contains redacted material: %s", auditFile)
	}
}

func TestChallengeReplayRejected(t *testing.T) {
	config := testConfig(t)
	runtime := newTestRuntime(t, config)
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	challenge, err := client.Challenge(context.Background(), &protocolv1.ChallengeRequest{
		ClusterId: config.ClusterID,
		NodeId:    config.DevelopmentSubject,
		Operation: protocolv1.Operation_OPERATION_WRAP,
	})
	if err != nil {
		t.Fatalf("Challenge returned error: %v", err)
	}
	evidence := testEvidence(challenge.GetChallengeId(), config.DevelopmentSubject)
	first, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{Plaintext: []byte("one"), Evidence: evidence})
	if err != nil {
		t.Fatalf("first Wrap returned error: %v", err)
	}
	if first.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("first decision = %s, want allow", first.GetDecision().GetState())
	}
	second, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{Plaintext: []byte("two"), Evidence: evidence})
	if err != nil {
		t.Fatalf("second Wrap returned error: %v", err)
	}
	if second.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("second decision = %s, want deny", second.GetDecision().GetState())
	}
}

func TestRevokedSubjectDenied(t *testing.T) {
	config := testConfig(t)
	runtime := newTestRuntime(t, config)
	if err := runtime.Store.RevokeSubject(context.Background(), config.ClusterID, config.DevelopmentSubject); err != nil {
		t.Fatalf("RevokeSubject returned error: %v", err)
	}
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	challenge, err := client.Challenge(context.Background(), &protocolv1.ChallengeRequest{
		ClusterId: config.ClusterID,
		NodeId:    config.DevelopmentSubject,
		Operation: protocolv1.Operation_OPERATION_WRAP,
	})
	if err != nil {
		t.Fatalf("Challenge returned error: %v", err)
	}
	resp, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: []byte("seal"),
		Evidence:  testEvidence(challenge.GetChallengeId(), config.DevelopmentSubject),
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("decision = %s, want deny", resp.GetDecision().GetState())
	}
}

func TestDecryptOnlyKeyCannotWrap(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	_, err := store.db.ExecContext(
		context.Background(),
		`UPDATE key_versions SET status = ? WHERE cluster_id = ? AND key_id = ? AND version = 1`,
		string(keyring.StatusDecryptOnly),
		config.ClusterID,
		config.KeyID,
	)
	if err != nil {
		t.Fatalf("update key version returned error: %v", err)
	}
	_, err = store.db.ExecContext(
		context.Background(),
		`INSERT INTO key_versions(cluster_id, key_id, version, status, algorithm, policy_id, material, created_at)
		 VALUES (?, ?, 2, ?, ?, ?, ?, ?)`,
		config.ClusterID,
		config.KeyID,
		string(keyring.StatusActive),
		string(keyring.AlgorithmAES256GCM),
		config.Policy(),
		bytes.Repeat([]byte{2}, keyring.KeySize),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		t.Fatalf("insert key version returned error: %v", err)
	}
	telemetry := newTestTelemetry(t)
	service := NewService(config, store, NewFileAuditSink(config.AuditFilePath, false), telemetry)
	challenge := testChallenge(t, config)
	if err := store.CreateChallenge(context.Background(), challenge); err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}

	resp, err := service.Wrap(context.Background(), &protocolv1.WrapRequest{
		RequestedKey: &protocolv1.KeyRef{ClusterId: config.ClusterID, KeyId: config.KeyID, Version: 1},
		Plaintext:    []byte("seal"),
		Evidence:     testEvidence(challenge.ID, config.DevelopmentSubject),
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("decision = %s, want deny", resp.GetDecision().GetState())
	}
}

func TestEvidenceVerifierFailureDeniesWrap(t *testing.T) {
	config := testConfig(t)
	store := newTestStore(t, config)
	telemetry := newTestTelemetry(t)
	service := NewServiceWithEvidenceVerifier(
		config,
		store,
		NewFileAuditSink(config.AuditFilePath, false),
		telemetry,
		failingEvidenceVerifier{},
	)

	resp, err := service.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: []byte("seal"),
		Evidence:  testEvidence("chal_test", config.DevelopmentSubject),
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("decision = %s, want deny", resp.GetDecision().GetState())
	}
	errs := resp.GetDecision().GetErrors()
	if len(errs) != 1 || errs[0].GetCode() != protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED {
		t.Fatalf("errors = %v, want attestation failure", errs)
	}
}

func TestKubernetesEvidenceVerifierAuthorizesWorkload(t *testing.T) {
	config := testConfig(t)
	config.DevelopmentSubject = testKubernetesSubject
	store := newTestStore(t, config)
	cache := NewMemoryNodeEvidenceCache()
	putTestNodeEvidence(t, cache, config, "node-uid", time.Now(), time.Now().Add(time.Minute))
	telemetry, err := NewTelemetry(config)
	if err != nil {
		t.Fatalf("NewTelemetry returned error: %v", err)
	}
	t.Cleanup(func() { _ = telemetry.Shutdown(context.Background()) })
	service := NewServiceWithEvidenceVerifierAndNodeEvidence(
		config,
		store,
		NewFileAuditSink(config.AuditFilePath, false),
		telemetry,
		testKubernetesEvidenceVerifier(testKubernetesTokenReviewStatus(testNodeName, "node-uid")),
		cache,
	)
	challenge := testChallenge(t, config)
	if err := store.CreateChallenge(context.Background(), challenge); err != nil {
		t.Fatalf("CreateChallenge returned error: %v", err)
	}
	evidence, err := k8sprovider.NewEvidenceEnvelope(challenge.ID, "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	resp, err := service.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: []byte("seal plaintext"),
		Evidence:  evidence,
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("wrap decision = %s, want allow", resp.GetDecision().GetState())
	}
	if !hasAuditDecision(
		readAuditEvents(t, config.AuditFilePath),
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
	) {
		t.Fatal("audit file does not contain an allow decision")
	}
}

func TestRuntimeKubernetesVerifierUsesTokenReviewAndPodLookup(t *testing.T) {
	api, calls := startKubernetesAPIServer(t, testNodeName)
	defer api.Close()
	config := testConfig(t)
	config.DevelopmentSubject = testKubernetesSubject
	config.Kubernetes = testRuntimeKubernetesConfig(t, api.URL)
	runtime := newTestRuntime(t, config)
	if runtime.NodeEvidence == nil {
		t.Fatal("runtime NodeEvidence cache is nil")
	}
	putTestNodeEvidence(t, runtime.NodeEvidence, config, "node-uid", time.Now(), time.Now().Add(time.Minute))
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	challengeID := brokerChallenge(t, client, config, config.DevelopmentSubject, protocolv1.Operation_OPERATION_WRAP)
	evidence, err := k8sprovider.NewEvidenceEnvelope(challengeID, "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	resp, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: []byte("seal plaintext"),
		Evidence:  evidence,
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("wrap decision = %s, want allow", resp.GetDecision().GetState())
	}
	if calls.tokenReviews() != 1 || calls.pods() != 1 {
		t.Fatalf("Kubernetes API calls = tokenreviews:%d pods:%d, want 1/1", calls.tokenReviews(), calls.pods())
	}
}

func TestRuntimeKubernetesVerifierDeniesPodNodeMismatch(t *testing.T) {
	api, calls := startKubernetesAPIServer(t, "node-b")
	defer api.Close()
	config := testConfig(t)
	config.DevelopmentSubject = testKubernetesSubject
	config.Kubernetes = testRuntimeKubernetesConfig(t, api.URL)
	runtime := newTestRuntime(t, config)
	client, cleanup := startPlaintextBroker(t, runtime)
	defer cleanup()

	challengeID := brokerChallenge(t, client, config, config.DevelopmentSubject, protocolv1.Operation_OPERATION_WRAP)
	evidence, err := k8sprovider.NewEvidenceEnvelope(challengeID, "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	resp, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: []byte("seal plaintext"),
		Evidence:  evidence,
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	assertDecisionError(
		t,
		resp.GetDecision(),
		protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
		protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
		"attestation verification failed",
	)
	if calls.tokenReviews() != 1 || calls.pods() != 1 {
		t.Fatalf("Kubernetes API calls = tokenreviews:%d pods:%d, want 1/1", calls.tokenReviews(), calls.pods())
	}
}

func TestKubernetesWorkloadNodeEvidencePolicyDenials(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name           string
		configureCache func(t *testing.T, cache *MemoryNodeEvidenceCache, config Config)
		wantReason     string
	}{
		{
			name:       "missing",
			wantReason: "node evidence is missing",
		},
		{
			name: "stale",
			configureCache: func(t *testing.T, cache *MemoryNodeEvidenceCache, config Config) {
				t.Helper()
				putTestNodeEvidence(
					t,
					cache,
					config,
					"node-uid",
					now.Add(-2*time.Minute),
					now.Add(-time.Minute),
				)
			},
			wantReason: "node evidence is stale",
		},
		{
			name: "uid-mismatch",
			configureCache: func(t *testing.T, cache *MemoryNodeEvidenceCache, config Config) {
				t.Helper()
				putTestNodeEvidence(t, cache, config, "other-node-uid", now, now.Add(time.Minute))
			},
			wantReason: "node evidence does not match workload node",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testConfig(t)
			config.DevelopmentSubject = testKubernetesSubject
			store := newTestStore(t, config)
			cache := NewMemoryNodeEvidenceCache()
			if tt.configureCache != nil {
				tt.configureCache(t, cache, config)
			}
			service := NewServiceWithEvidenceVerifierAndNodeEvidence(
				config,
				store,
				NewFileAuditSink(config.AuditFilePath, false),
				newTestTelemetry(t),
				testKubernetesEvidenceVerifier(testKubernetesTokenReviewStatus(testNodeName, "node-uid")),
				cache,
			)
			challenge := testChallenge(t, config)
			if err := store.CreateChallenge(context.Background(), challenge); err != nil {
				t.Fatalf("CreateChallenge returned error: %v", err)
			}
			evidence, err := k8sprovider.NewEvidenceEnvelope(challenge.ID, "projected-token")
			if err != nil {
				t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
			}

			resp, err := service.Wrap(context.Background(), &protocolv1.WrapRequest{
				Plaintext: []byte("seal plaintext"),
				Evidence:  evidence,
			})
			if err != nil {
				t.Fatalf("Wrap returned error: %v", err)
			}
			assertDecisionError(
				t,
				resp.GetDecision(),
				protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
				protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
				tt.wantReason,
			)
		})
	}
}

func TestTelemetryAttributesDoNotIncludeSecretMaterial(t *testing.T) {
	attrs := safeAttributes(
		"prod-eu1",
		"root",
		1,
		protocolv1.Operation_OPERATION_WRAP,
		Allow("development"),
		"audit_123",
	)
	encodedKey := base64.StdEncoding.EncodeToString(testKeyMaterial())
	joined := attributesString(attrs)
	if strings.Contains(joined, "plaintext") || strings.Contains(joined, encodedKey) {
		t.Fatalf("telemetry attributes contain secret material: %s", joined)
	}
}

func TestStdoutTelemetryExporterCanShutdown(t *testing.T) {
	config := testConfig(t)
	config.OTelExporter = OTelExporterStdout
	telemetry, err := NewTelemetry(config)
	if err != nil {
		t.Fatalf("NewTelemetry returned error: %v", err)
	}
	attrs := safeAttributes(
		config.ClusterID,
		config.KeyID,
		1,
		protocolv1.Operation_OPERATION_WRAP,
		Allow(config.Policy()),
		"audit_123",
	)
	telemetry.recordWrap(context.Background(), attrs)
	if err := telemetry.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
}

func TestTLSHarnessTrustedAndUntrustedClients(t *testing.T) {
	config := testConfig(t)
	pki := newTestPKI(t)
	config.AllowPlaintextForTests = false
	config.TLSCertFile = pki.serverCert
	config.TLSKeyFile = pki.serverKey
	config.ClientCAFile = pki.caCert
	config.RequireClientCert = true
	runtime := newTestRuntime(t, config)
	listener := startRuntimeOnListener(t, runtime)
	defer func() { _ = runtime.Close(context.Background()) }()

	trusted := dialTLS(t, listener.Addr().String(), pki.caCert, "localhost", pki.clientCert, pki.clientKey)
	defer func() { _ = trusted.Close() }()
	if _, err := statusClient(trusted, config); err != nil {
		t.Fatalf("trusted Status returned error: %v", err)
	}

	untrustedPKI := newTestPKI(t)
	untrusted := dialTLS(
		t,
		listener.Addr().String(),
		pki.caCert,
		"localhost",
		untrustedPKI.clientCert,
		untrustedPKI.clientKey,
	)
	defer func() { _ = untrusted.Close() }()
	if _, err := statusClient(untrusted, config); err == nil {
		t.Fatal("untrusted client Status returned nil error")
	}
}

func TestTLSExpiredClientDenied(t *testing.T) {
	config := testConfig(t)
	pki := newTestPKI(t)
	expiredCert, expiredKey := newLeafCertificate(t, pki.caCertificate, pki.caKey, "expired-client", false, true)
	expiredCertPath := writePEM(t, pki.dir, "expired-client.crt", expiredCert)
	expiredKeyPath := writePEM(t, pki.dir, "expired-client.key", expiredKey)
	config.AllowPlaintextForTests = false
	config.TLSCertFile = pki.serverCert
	config.TLSKeyFile = pki.serverKey
	config.ClientCAFile = pki.caCert
	config.RequireClientCert = true
	runtime := newTestRuntime(t, config)
	listener := startRuntimeOnListener(t, runtime)
	defer func() { _ = runtime.Close(context.Background()) }()

	conn := dialTLS(t, listener.Addr().String(), pki.caCert, "localhost", expiredCertPath, expiredKeyPath)
	defer func() { _ = conn.Close() }()
	if _, err := statusClient(conn, config); err == nil {
		t.Fatal("expired client Status returned nil error")
	}
}

func TestTLSServerNameMismatchDenied(t *testing.T) {
	config := testConfig(t)
	pki := newTestPKI(t)
	config.AllowPlaintextForTests = false
	config.TLSCertFile = pki.serverCert
	config.TLSKeyFile = pki.serverKey
	runtime := newTestRuntime(t, config)
	listener := startRuntimeOnListener(t, runtime)
	defer func() { _ = runtime.Close(context.Background()) }()

	conn := dialTLS(t, listener.Addr().String(), pki.caCert, "wrong.local", "", "")
	defer func() { _ = conn.Close() }()
	if _, err := statusClient(conn, config); err == nil {
		t.Fatal("wrong-name TLS client returned nil error")
	}
}

func TestPlaintextRequiresExplicitTestConfig(t *testing.T) {
	config := testConfig(t)
	config.AllowPlaintextForTests = false
	config.TLSCertFile = ""
	config.TLSKeyFile = ""
	if _, err := NewGRPCServer(config, nil, nil); err == nil {
		t.Fatal("NewGRPCServer returned nil error without TLS")
	}
}

func brokerWrap(
	t *testing.T,
	client protocolv1.UnsealServiceClient,
	config Config,
	subject string,
	plaintext []byte,
	aad []byte,
) *protocolv1.WrappedBlob {
	t.Helper()
	challenge := brokerChallenge(t, client, config, subject, protocolv1.Operation_OPERATION_WRAP)
	resp, err := client.Wrap(context.Background(), &protocolv1.WrapRequest{
		Plaintext: plaintext,
		Aad:       aad,
		Evidence:  testEvidence(challenge, subject),
	})
	if err != nil {
		t.Fatalf("Wrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("wrap decision = %s, want allow", resp.GetDecision().GetState())
	}
	return resp.GetBlob()
}

func brokerUnwrap(
	t *testing.T,
	client protocolv1.UnsealServiceClient,
	config Config,
	subject string,
	blob *protocolv1.WrappedBlob,
	aad []byte,
) []byte {
	t.Helper()
	challenge := brokerChallenge(t, client, config, subject, protocolv1.Operation_OPERATION_UNWRAP)
	resp, err := client.Unwrap(context.Background(), &protocolv1.UnwrapRequest{
		Blob:     blob,
		Aad:      aad,
		Evidence: testEvidence(challenge, subject),
	})
	if err != nil {
		t.Fatalf("Unwrap returned error: %v", err)
	}
	if resp.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("unwrap decision = %s, want allow", resp.GetDecision().GetState())
	}
	return resp.GetPlaintext()
}

func brokerChallenge(
	t *testing.T,
	client protocolv1.UnsealServiceClient,
	config Config,
	subject string,
	operation protocolv1.Operation,
) string {
	t.Helper()
	challenge, err := client.Challenge(context.Background(), &protocolv1.ChallengeRequest{
		ClusterId: config.ClusterID,
		NodeId:    subject,
		Operation: operation,
	})
	if err != nil {
		t.Fatalf("Challenge returned error: %v", err)
	}
	return challenge.GetChallengeId()
}

func statusClient(conn *grpc.ClientConn, config Config) (*protocolv1.StatusResponse, error) {
	return protocolv1.NewUnsealServiceClient(conn).Status(
		context.Background(),
		&protocolv1.StatusRequest{ClusterId: config.ClusterID},
	)
}

func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		ListenAddress:             "127.0.0.1:0",
		AllowPlaintextForTests:    true,
		SQLitePath:                filepath.Join(dir, "broker.db"),
		AuditFilePath:             filepath.Join(dir, "audit.jsonl"),
		KeyringProtectionProfile:  DevelopmentProfile,
		OTelExporter:              OTelExporterNone,
		ClusterID:                 "prod-eu1",
		KeyID:                     "root",
		PolicyID:                  "development",
		DevelopmentSubject:        testNodeName,
		DevelopmentWrappingKeyB64: base64.StdEncoding.EncodeToString(testKeyMaterial()),
		ChallengeTTLSeconds:       60,
	}
}

func testKeyMaterial() []byte {
	return bytes.Repeat([]byte{1}, keyring.KeySize)
}

func newTestStore(t *testing.T, config Config) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLiteStore(context.Background(), config.SQLitePath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore returned error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	key, err := config.DevelopmentWrappingKey()
	if err != nil {
		t.Fatalf("DevelopmentWrappingKey returned error: %v", err)
	}
	if err := store.ConfigureDevelopment(context.Background(), config, key); err != nil {
		t.Fatalf("ConfigureDevelopment returned error: %v", err)
	}
	return store
}

func newTestRuntime(t *testing.T, config Config) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime
}

func newTestTelemetry(t *testing.T) *Telemetry {
	t.Helper()
	telemetry, err := NewTelemetry(testConfig(t))
	if err != nil {
		t.Fatalf("NewTelemetry returned error: %v", err)
	}
	return telemetry
}

func startPlaintextBroker(t *testing.T, runtime *Runtime) (protocolv1.UnsealServiceClient, func()) {
	t.Helper()
	listener := startRuntimeOnListener(t, runtime)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	return protocolv1.NewUnsealServiceClient(conn), func() {
		_ = conn.Close()
		_ = runtime.Close(context.Background())
	}
}

func startRuntimeOnListener(t *testing.T, runtime *Runtime) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	go func() {
		_ = runtime.Server.Serve(listener)
	}()
	return listener
}

func testChallenge(t *testing.T, config Config) Challenge {
	t.Helper()
	id, err := randomID("chal")
	if err != nil {
		t.Fatalf("randomID returned error: %v", err)
	}
	nonce, err := randomNonce()
	if err != nil {
		t.Fatalf("randomNonce returned error: %v", err)
	}
	now := time.Now()
	return Challenge{
		ID:        id,
		Nonce:     nonce,
		ClusterID: config.ClusterID,
		Subject:   config.DevelopmentSubject,
		Operation: protocolv1.Operation_OPERATION_WRAP,
		ExpiresAt: now.Add(config.ChallengeTTL()),
		CreatedAt: now,
	}
}

func testEvidence(challengeID string, subject string) *protocolv1.EvidenceEnvelope {
	return &protocolv1.EvidenceEnvelope{
		Provider:    protocolv1.AttestationProvider_ATTESTATION_PROVIDER_UNSPECIFIED,
		Format:      "development-subject",
		ChallengeId: challengeID,
		NormalizedClaims: []*protocolv1.Claim{
			{Namespace: SubjectClaimNamespace, Name: SubjectClaimName, Value: subject},
		},
	}
}

func testRuntimeKubernetesConfig(t *testing.T, apiServer string) KubernetesConfig {
	t.Helper()
	return KubernetesConfig{
		Enabled:                true,
		APIServer:              apiServer,
		BearerTokenFile:        writeKubernetesBearerToken(t),
		TokenReviewAudience:    "bao-unseald",
		Namespace:              "openbao",
		ServiceAccount:         "openbao",
		NodeEvidenceTTLSeconds: 30,
		APITimeoutSeconds:      5,
	}
}

func writeKubernetesBearerToken(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("reviewer-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}

type kubernetesAPICalls struct {
	mu               sync.Mutex
	tokenReviewCount int
	podCount         int
}

func (c *kubernetesAPICalls) tokenReview() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokenReviewCount++
}

func (c *kubernetesAPICalls) pod() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.podCount++
}

func (c *kubernetesAPICalls) tokenReviews() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokenReviewCount
}

func (c *kubernetesAPICalls) pods() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.podCount
}

func startKubernetesAPIServer(t *testing.T, podNodeName string) (*httptest.Server, *kubernetesAPICalls) {
	t.Helper()
	calls := &kubernetesAPICalls{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer reviewer-token" {
			t.Errorf("authorization = %q, want reviewer bearer token", got)
		}
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			calls.tokenReview()
			var reviewed struct {
				Spec struct {
					Token     string   `json:"token,omitempty"`
					Audiences []string `json:"audiences,omitempty"`
				} `json:"spec,omitempty"`
			}
			if err := json.NewDecoder(r.Body).Decode(&reviewed); err != nil {
				t.Errorf("Decode TokenReview request returned error: %v", err)
			}
			if reviewed.Spec.Token != "projected-token" {
				t.Errorf("reviewed token = %q, want projected-token", reviewed.Spec.Token)
			}
			if len(reviewed.Spec.Audiences) != 1 || reviewed.Spec.Audiences[0] != "bao-unseald" {
				t.Errorf("reviewed audiences = %v, want [bao-unseald]", reviewed.Spec.Audiences)
			}
			_, _ = w.Write([]byte(`{
  "status": {
    "authenticated": true,
    "user": {
      "username": "system:serviceaccount:openbao:openbao",
      "uid": "sa-uid",
      "groups": ["system:serviceaccounts"],
      "extra": {
        "authentication.kubernetes.io/pod-name": ["openbao-0"],
        "authentication.kubernetes.io/pod-uid": ["pod-uid"],
        "authentication.kubernetes.io/node-name": ["node-a"],
        "authentication.kubernetes.io/node-uid": ["node-uid"]
      }
    },
    "audiences": ["bao-unseald"]
  }
}`))
		case "/api/v1/namespaces/openbao/pods/openbao-0":
			calls.pod()
			_, _ = w.Write([]byte(`{
  "metadata": {
    "namespace": "openbao",
    "name": "openbao-0",
    "uid": "pod-uid"
  },
  "spec": {
    "nodeName": "` + podNodeName + `"
  }
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return server, calls
}

func writePolicyDocument(t *testing.T, config Config, subject string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	raw := `{
  "policy_id": "` + config.Policy() + `",
  "mode": "development-subject",
  "development_subjects": ["` + subject + `"]
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}

func readAuditFile(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- test helper reads the audit path generated by the test config.
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer func() { _ = file.Close() }()
	var out strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		out.WriteString(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner returned error: %v", err)
	}
	return out.String()
}

func readAuditEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()
	// #nosec G304 -- test helper reads the audit path generated by the test config.
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer func() { _ = file.Close() }()

	var events []AuditEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("Unmarshal audit event returned error: %v", err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner returned error: %v", err)
	}
	return events
}

func hasAuditDecision(events []AuditEvent, decision protocolv1.PolicyDecisionState) bool {
	for _, event := range events {
		if event.Decision == decision.String() {
			return true
		}
	}
	return false
}

func assertDecisionError(
	t *testing.T,
	decision *protocolv1.PolicyDecision,
	state protocolv1.PolicyDecisionState,
	code protocolv1.ErrorCode,
	reason string,
) {
	t.Helper()
	if decision.GetState() != state {
		t.Fatalf("decision = %s, want %s", decision.GetState(), state)
	}
	errs := decision.GetErrors()
	if len(errs) != 1 {
		t.Fatalf("decision errors = %v, want one error", errs)
	}
	if errs[0].GetCode() != code || errs[0].GetMessage() != reason {
		t.Fatalf("decision error = (%s, %q), want (%s, %q)", errs[0].GetCode(), errs[0].GetMessage(), code, reason)
	}
}

func attributesString(attrs []attribute.KeyValue) string {
	var builder strings.Builder
	for _, attr := range attrs {
		builder.WriteString(attr.Value.AsString())
		builder.WriteByte('|')
	}
	return builder.String()
}

type testPKI struct {
	dir           string
	caCert        string
	caKey         *ecdsa.PrivateKey
	caCertificate *x509.Certificate
	serverCert    string
	serverKey     string
	clientCert    string
	clientKey     string
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()
	caCertPEM, caKey, caCert := newCertificateAuthority(t)
	serverCert, serverKey := newLeafCertificate(t, caCert, caKey, "localhost", true, false)
	clientCert, clientKey := newLeafCertificate(t, caCert, caKey, "client", false, false)
	return testPKI{
		dir:           dir,
		caCert:        writePEM(t, dir, "ca.crt", caCertPEM),
		caKey:         caKey,
		caCertificate: caCert,
		serverCert:    writePEM(t, dir, "server.crt", serverCert),
		serverKey:     writePEM(t, dir, "server.key", serverKey),
		clientCert:    writePEM(t, dir, "client.crt", clientCert),
		clientKey:     writePEM(t, dir, "client.key", clientKey),
	}
}

func newCertificateAuthority(t *testing.T) ([]byte, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key, template
}

func newLeafCertificate(
	t *testing.T,
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	commonName string,
	server bool,
	expired bool,
) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	notBefore := time.Now().Add(-time.Minute)
	notAfter := time.Now().Add(time.Hour)
	if expired {
		notBefore = time.Now().Add(-2 * time.Hour)
		notAfter = time.Now().Add(-time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{commonName}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey returned error: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writePEM(t *testing.T, dir string, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}

func dialTLS(
	t *testing.T,
	address string,
	caPath string,
	serverName string,
	clientCertPath string,
	clientKeyPath string,
) *grpc.ClientConn {
	t.Helper()
	// #nosec G304 -- test helper reads the generated CA path for the local TLS harness.
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("AppendCertsFromPEM returned false")
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: serverName,
	}
	if clientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			t.Fatalf("LoadX509KeyPair returned error: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}
	return conn
}

func putTestNodeEvidence(
	t *testing.T,
	cache *MemoryNodeEvidenceCache,
	config Config,
	nodeUID string,
	collectedAt time.Time,
	expiresAt time.Time,
) {
	t.Helper()
	err := cache.PutNodeEvidence(context.Background(), NodeEvidence{
		ClusterID:    config.ClusterID,
		NodeName:     testNodeName,
		NodeUID:      nodeUID,
		Provider:     "generic-tpm2-quote",
		EvidenceHash: "test-node-evidence-hash",
		CollectedAt:  collectedAt,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		t.Fatalf("PutNodeEvidence returned error: %v", err)
	}
}

func testKubernetesEvidenceVerifier(status k8sprovider.TokenReviewStatus) KubernetesEvidenceVerifier {
	return NewKubernetesEvidenceVerifier(staticKubernetesReviewer{status: status}, KubernetesConfig{
		TokenReviewAudience: "bao-unseald",
		Namespace:           "openbao",
		ServiceAccount:      "openbao",
	})
}

func testKubernetesTokenReviewStatus(nodeName string, nodeUID string) k8sprovider.TokenReviewStatus {
	return k8sprovider.TokenReviewStatus{
		Authenticated: true,
		User: k8sprovider.UserInfo{
			Username: "system:serviceaccount:openbao:openbao",
			Extra: map[string][]string{
				"authentication.kubernetes.io/pod-name":  {"openbao-0"},
				"authentication.kubernetes.io/pod-uid":   {"pod-uid"},
				"authentication.kubernetes.io/node-name": {nodeName},
				"authentication.kubernetes.io/node-uid":  {nodeUID},
			},
		},
		Audiences: []string{"bao-unseald"},
	}
}

type failingEvidenceVerifier struct{}

func (failingEvidenceVerifier) VerifyEvidence(
	context.Context,
	*protocolv1.EvidenceEnvelope,
) (VerifiedEvidence, error) {
	return VerifiedEvidence{}, errors.New("test verifier failure")
}

type staticKubernetesReviewer struct {
	status k8sprovider.TokenReviewStatus
}

func (r staticKubernetesReviewer) ReviewToken(
	context.Context,
	k8sprovider.TokenReviewRequest,
) (k8sprovider.TokenReviewStatus, error) {
	return r.status, nil
}
