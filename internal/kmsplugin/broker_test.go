package kmsplugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"
	"time"

	brokerpkg "github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
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
	t.Cleanup(func() { _ = runtime.Close() })
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
