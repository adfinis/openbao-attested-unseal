package kmsplugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	brokerpkg "github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

func TestBrokerBackendWrapsActiveVersionAndUnwrapsDecryptOnlyVersion(t *testing.T) {
	ctx := context.Background()
	runtime := newBrokerRuntimeForPlugin(t)
	listener := startBrokerRuntimeForPlugin(t, runtime)
	backend, err := newBrokerBackend(ctx, Config{
		Mode:            ModeBroker,
		BrokerAddress:   listener.Addr().String(),
		BrokerPlaintext: true,
		ClusterID:       runtime.Config.ClusterID,
		NodeID:          runtime.Config.DevelopmentSubject,
	})
	if err != nil {
		t.Fatalf("newBrokerBackend returned error: %v", err)
	}
	defer func() { _ = backend.Close(ctx) }()

	oldBlob, err := backend.Encrypt(ctx, EncryptRequest{
		Plaintext: []byte("old seal plaintext"),
		AAD:       []byte("aad"),
	})
	if err != nil {
		t.Fatalf("Encrypt old blob returned error: %v", err)
	}
	if oldBlob.Blob.GetKeyInfo().GetKeyId() != "prod-eu1/root/v1" {
		t.Fatalf("old blob key = %q, want prod-eu1/root/v1", oldBlob.Blob.GetKeyInfo().GetKeyId())
	}

	rotateBrokerKeyringForPlugin(t, runtime)
	keyID, err := backend.KeyID(ctx)
	if err != nil {
		t.Fatalf("KeyID returned error after rotation: %v", err)
	}
	if keyID != "prod-eu1/root/v2" {
		t.Fatalf("KeyID = %q, want prod-eu1/root/v2", keyID)
	}

	newBlob, err := backend.Encrypt(ctx, EncryptRequest{
		Plaintext: []byte("new seal plaintext"),
		AAD:       []byte("aad"),
	})
	if err != nil {
		t.Fatalf("Encrypt new blob returned error: %v", err)
	}
	if newBlob.Blob.GetKeyInfo().GetKeyId() != "prod-eu1/root/v2" {
		t.Fatalf("new blob key = %q, want prod-eu1/root/v2", newBlob.Blob.GetKeyInfo().GetKeyId())
	}

	oldPlaintext, err := backend.Decrypt(ctx, DecryptRequest{
		Blob: oldBlob.Blob,
		AAD:  []byte("aad"),
	})
	if err != nil {
		t.Fatalf("Decrypt old blob returned error: %v", err)
	}
	if string(oldPlaintext.Plaintext) != "old seal plaintext" {
		t.Fatalf("old plaintext = %q, want old seal plaintext", oldPlaintext.Plaintext)
	}
}

func TestBrokerBackendUsesKubernetesEvidence(t *testing.T) {
	ctx := context.Background()
	api := startPluginKubernetesAPIServer(t)
	defer api.Close()
	runtime := newKubernetesBrokerRuntimeForPlugin(t, api.URL)
	listener := startBrokerRuntimeForPlugin(t, runtime)
	backend, err := newBrokerBackend(ctx, Config{
		Mode:                ModeBroker,
		BrokerAddress:       listener.Addr().String(),
		BrokerPlaintext:     true,
		ClusterID:           runtime.Config.ClusterID,
		NodeID:              "openbao.openbao",
		EvidenceMode:        EvidenceModeKubernetesWorkload,
		KubernetesTokenFile: writePluginTokenFile(t, "projected-token\n"),
	})
	if err != nil {
		t.Fatalf("newBrokerBackend returned error: %v", err)
	}
	defer func() { _ = backend.Close(ctx) }()

	encrypted, err := backend.Encrypt(ctx, EncryptRequest{
		Plaintext: []byte("kubernetes seal plaintext"),
		AAD:       []byte("aad"),
	})
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	plaintext, err := backend.Decrypt(ctx, DecryptRequest{
		Blob: encrypted.Blob,
		AAD:  []byte("aad"),
	})
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if string(plaintext.Plaintext) != "kubernetes seal plaintext" {
		t.Fatalf("plaintext = %q, want kubernetes seal plaintext", plaintext.Plaintext)
	}
}

func TestBrokerBackendKubernetesEvidenceReadsTokenFile(t *testing.T) {
	tokenFile := writePluginTokenFile(t, "projected-token\n")
	backend := brokerBackend{
		config: Config{
			EvidenceMode:        EvidenceModeKubernetesWorkload,
			KubernetesTokenFile: tokenFile,
		},
	}
	evidence, err := backend.evidence("chal_test")
	if err != nil {
		t.Fatalf("evidence returned error: %v", err)
	}
	if evidence.GetProvider() != protocolv1.AttestationProvider_ATTESTATION_PROVIDER_KUBERNETES_WORKLOAD {
		t.Fatalf("provider = %s, want Kubernetes workload", evidence.GetProvider())
	}
	if evidence.GetFormat() != k8sprovider.EvidenceFormat {
		t.Fatalf("format = %q, want %s", evidence.GetFormat(), k8sprovider.EvidenceFormat)
	}
	var payload k8sprovider.EvidencePayload
	if err := json.Unmarshal(evidence.GetPayload(), &payload); err != nil {
		t.Fatalf("Unmarshal payload returned error: %v", err)
	}
	if payload.Token != "projected-token" {
		t.Fatalf("token = %q, want projected-token", payload.Token)
	}
}

func TestBrokerBackendKubernetesEvidenceRejectsEmptyTokenFile(t *testing.T) {
	backend := brokerBackend{
		config: Config{
			EvidenceMode:        EvidenceModeKubernetesWorkload,
			KubernetesTokenFile: writePluginTokenFile(t, "\n"),
		},
	}
	if _, err := backend.evidence("chal_test"); err == nil {
		t.Fatal("evidence returned nil error")
	}
}

func newBrokerRuntimeForPlugin(t *testing.T) *brokerpkg.Runtime {
	t.Helper()
	dir := t.TempDir()
	config := brokerpkg.Config{
		ListenAddress:             "127.0.0.1:0",
		AllowPlaintextForTests:    true,
		SQLitePath:                filepath.Join(dir, "broker.db"),
		AuditFilePath:             filepath.Join(dir, "audit.jsonl"),
		KeyringProtectionProfile:  brokerpkg.DevelopmentProfile,
		OTelExporter:              brokerpkg.OTelExporterNone,
		ClusterID:                 "prod-eu1",
		KeyID:                     "root",
		PolicyID:                  "development",
		DevelopmentSubject:        "node-a",
		DevelopmentWrappingKeyB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, keyring.KeySize)),
		ChallengeTTLSeconds:       60,
	}
	runtime, err := brokerpkg.NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return runtime
}

func newKubernetesBrokerRuntimeForPlugin(t *testing.T, apiServer string) *brokerpkg.Runtime {
	t.Helper()
	dir := t.TempDir()
	config := brokerpkg.Config{
		ListenAddress:             "127.0.0.1:0",
		AllowPlaintextForTests:    true,
		SQLitePath:                filepath.Join(dir, "broker.db"),
		AuditFilePath:             filepath.Join(dir, "audit.jsonl"),
		KeyringProtectionProfile:  brokerpkg.DevelopmentProfile,
		OTelExporter:              brokerpkg.OTelExporterNone,
		ClusterID:                 "prod-eu1",
		KeyID:                     "root",
		PolicyID:                  "development",
		DevelopmentSubject:        "openbao.openbao",
		DevelopmentWrappingKeyB64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, keyring.KeySize)),
		ChallengeTTLSeconds:       60,
		Kubernetes: brokerpkg.KubernetesConfig{
			Enabled:                true,
			APIServer:              apiServer,
			BearerTokenFile:        writePluginTokenFile(t, "reviewer-token\n"),
			TokenReviewAudience:    "bao-unseald",
			Namespace:              "openbao",
			ServiceAccount:         "openbao",
			NodeEvidenceTTLSeconds: 30,
			APITimeoutSeconds:      5,
		},
	}
	runtime, err := brokerpkg.NewRuntime(context.Background(), config)
	if err != nil {
		t.Fatalf("NewRuntime returned error: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	if runtime.NodeEvidence == nil {
		t.Fatal("runtime NodeEvidence cache is nil")
	}
	err = runtime.NodeEvidence.PutNodeEvidence(context.Background(), brokerpkg.NodeEvidence{
		ClusterID:    config.ClusterID,
		NodeName:     "node-a",
		NodeUID:      "node-uid",
		Provider:     "fake-local",
		EvidenceHash: "test-node-evidence-hash",
		CollectedAt:  time.Now(),
		ExpiresAt:    time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("PutNodeEvidence returned error: %v", err)
	}
	return runtime
}

func startBrokerRuntimeForPlugin(t *testing.T, runtime *brokerpkg.Runtime) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		_ = runtime.Server.Serve(listener)
	}()
	return listener
}

func rotateBrokerKeyringForPlugin(t *testing.T, runtime *brokerpkg.Runtime) {
	t.Helper()
	operation, err := runtime.Store.StartRotation(context.Background(), brokerpkg.RotationStartRequest{
		OperationID: "rot_plugin_test",
		ClusterID:   runtime.Config.ClusterID,
		KeyID:       runtime.Config.KeyID,
		PolicyID:    runtime.Config.Policy(),
		Material:    bytes.Repeat([]byte{2}, keyring.KeySize),
		CreatedAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("StartRotation returned error: %v", err)
	}
	if _, err := runtime.Store.ActivateRotation(context.Background(), operation.OperationID, time.Now()); err != nil {
		t.Fatalf("ActivateRotation returned error: %v", err)
	}
}

func writePluginTokenFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "workload.jwt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}

func startPluginKubernetesAPIServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer reviewer-token" {
			t.Errorf("authorization = %q, want reviewer bearer token", got)
		}
		switch r.URL.Path {
		case "/apis/authentication.k8s.io/v1/tokenreviews":
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
			_, _ = w.Write([]byte(`{
  "metadata": {
    "namespace": "openbao",
    "name": "openbao-0",
    "uid": "pod-uid"
  },
  "spec": {
    "nodeName": "node-a"
  }
}`))
		default:
			http.NotFound(w, r)
		}
	}))
}
