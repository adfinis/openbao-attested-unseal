package kmsplugin

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/dc-tec/openbao-attested-unseal/internal/keyring"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestWrapperEncryptBeforeInitFailsClosed(t *testing.T) {
	wrapper := NewWrapperWithFactory(inMemoryFactory{backend: newTestInMemoryBackend(t)})
	_, err := wrapper.Encrypt(context.Background(), []byte("plaintext"))
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Encrypt error = %v, want ErrNotInitialized", err)
	}
}

func TestWrapperDecryptBeforeInitFailsClosed(t *testing.T) {
	wrapper := NewWrapperWithFactory(inMemoryFactory{backend: newTestInMemoryBackend(t)})
	_, err := wrapper.Decrypt(context.Background(), &wrapping.BlobInfo{})
	if !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("Decrypt error = %v, want ErrNotInitialized", err)
	}
}

func TestWrapperLifecycleDelegatesToBackend(t *testing.T) {
	backend := newTestInMemoryBackend(t)
	wrapper := NewWrapperWithFactory(inMemoryFactory{backend: backend})
	config, err := wrapper.SetConfig(
		context.Background(),
		wrapping.WithConfigMap(validConfigMap()),
	)
	if err != nil {
		t.Fatalf("SetConfig returned error: %v", err)
	}
	if config.GetMetadata()["type"] != WrapperType.String() {
		t.Fatalf("wrapper type metadata = %q, want %q", config.GetMetadata()["type"], WrapperType)
	}
	if err := wrapper.Init(context.Background()); err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	blob, err := wrapper.Encrypt(context.Background(), []byte("plaintext"), wrapping.WithAad([]byte("aad")))
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if blob.GetKeyInfo().GetKeyId() != "prod-eu1/root/v1" {
		t.Fatalf("key ID = %q, want prod-eu1/root/v1", blob.GetKeyInfo().GetKeyId())
	}
	if blob.GetKeyInfo().GetMechanism() != keyring.BlobMechanismAES256GCM {
		t.Fatalf("mechanism = %d, want %d", blob.GetKeyInfo().GetMechanism(), keyring.BlobMechanismAES256GCM)
	}
	plaintext, err := wrapper.Decrypt(context.Background(), blob, wrapping.WithAad([]byte("aad")))
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if string(plaintext) != "plaintext" {
		t.Fatalf("plaintext = %q, want plaintext", plaintext)
	}
	keyID, err := wrapper.KeyId(context.Background())
	if err != nil {
		t.Fatalf("KeyId returned error: %v", err)
	}
	if keyID != "prod-eu1/root/v1" {
		t.Fatalf("key ID = %q, want prod-eu1/root/v1", keyID)
	}
	if err := wrapper.Finalize(context.Background()); err != nil {
		t.Fatalf("Finalize returned error: %v", err)
	}
	if !backend.Closed {
		t.Fatal("backend was not closed")
	}
}

func TestShouldServePluginUsesOpenBaoMagicCookie(t *testing.T) {
	t.Setenv(MagicCookieKey, "")
	if ShouldServePlugin() {
		t.Fatal("ShouldServePlugin returned true without magic cookie")
	}
	t.Setenv(MagicCookieKey, "set-by-openbao")
	if !ShouldServePlugin() {
		t.Fatal("ShouldServePlugin returned false with magic cookie")
	}
}

func validConfigMap() map[string]string {
	return map[string]string{
		configKeyMode:          string(ModeBroker),
		configKeyBrokerAddress: "unix:///run/bao-unseald/broker.sock",
		configKeyClusterID:     "prod-eu1",
		configKeyKeyID:         "root",
		configKeyKeyVersion:    "1",
		configKeyPolicyID:      "secureboot",
	}
}

func newTestInMemoryBackend(t *testing.T) *InMemoryBackend {
	t.Helper()
	ring, err := keyring.NewRing(keyring.KeyVersion{
		Ref: keyring.KeyRef{
			ClusterID: "prod-eu1",
			KeyID:     "root",
			Version:   1,
		},
		Status:    keyring.StatusActive,
		Algorithm: keyring.AlgorithmAES256GCM,
		PolicyID:  "secureboot",
		Material:  bytes.Repeat([]byte{1}, keyring.KeySize),
	})
	if err != nil {
		t.Fatalf("NewRing returned error: %v", err)
	}
	return &InMemoryBackend{Ring: ring, Mode: ModeBroker}
}
