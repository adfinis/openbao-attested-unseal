package keyring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ring := testActiveRing(t)
	blob, err := ring.Encrypt(context.Background(), []byte("seal plaintext"), []byte("openbao aad"))
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if blob.GetKeyInfo().GetKeyId() != "prod-eu1/root/v1" {
		t.Fatalf("key ID = %q, want prod-eu1/root/v1", blob.GetKeyInfo().GetKeyId())
	}
	if blob.GetKeyInfo().GetMechanism() != BlobMechanismAES256GCM {
		t.Fatalf("mechanism = %d, want %d", blob.GetKeyInfo().GetMechanism(), BlobMechanismAES256GCM)
	}
	if len(blob.GetIv()) != NonceSize {
		t.Fatalf("nonce size = %d, want %d", len(blob.GetIv()), NonceSize)
	}

	plaintext, err := ring.Decrypt(context.Background(), blob, []byte("openbao aad"))
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if string(plaintext) != "seal plaintext" {
		t.Fatalf("plaintext = %q, want seal plaintext", plaintext)
	}
}

func TestDecryptRejectsAADMismatch(t *testing.T) {
	ring := testActiveRing(t)
	blob, err := ring.Encrypt(context.Background(), []byte("seal plaintext"), []byte("good aad"))
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	if _, err := ring.Decrypt(context.Background(), blob, []byte("bad aad")); err == nil {
		t.Fatal("Decrypt returned nil error for mismatched AAD")
	}
}

func TestDecryptOnlyKeyDecryptsOldBlob(t *testing.T) {
	oldActive := testActiveRing(t)
	blob, err := oldActive.Encrypt(context.Background(), []byte("old seal plaintext"), nil)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	newRing, err := NewRing(
		testVersion(StatusDecryptOnly, 1),
		testVersion(StatusActive, 2),
	)
	if err != nil {
		t.Fatalf("NewRing returned error: %v", err)
	}

	plaintext, err := newRing.Decrypt(context.Background(), blob, nil)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	if string(plaintext) != "old seal plaintext" {
		t.Fatalf("plaintext = %q, want old seal plaintext", plaintext)
	}

	newBlob, err := newRing.Encrypt(context.Background(), []byte("new seal plaintext"), nil)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	if got := newBlob.GetKeyInfo().GetKeyId(); got != "prod-eu1/root/v2" {
		t.Fatalf("new blob key ID = %q, want prod-eu1/root/v2", got)
	}
}

func TestRetiredKeyCannotDecrypt(t *testing.T) {
	oldActive := testActiveRing(t)
	blob, err := oldActive.Encrypt(context.Background(), []byte("old seal plaintext"), nil)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	newRing, err := NewRing(
		testVersion(StatusRetired, 1),
		testVersion(StatusActive, 2),
	)
	if err != nil {
		t.Fatalf("NewRing returned error: %v", err)
	}

	if _, err := newRing.Decrypt(context.Background(), blob, nil); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Decrypt error = %v, want ErrKeyNotUsable", err)
	}
}

func TestUnknownKeyVersionFails(t *testing.T) {
	oldActive := testActiveRing(t)
	blob, err := oldActive.Encrypt(context.Background(), []byte("old seal plaintext"), nil)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}

	newRing, err := NewRing(testVersion(StatusActive, 2))
	if err != nil {
		t.Fatalf("NewRing returned error: %v", err)
	}
	if _, err := newRing.Decrypt(context.Background(), blob, nil); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Decrypt error = %v, want ErrKeyNotFound", err)
	}
}

func TestMalformedBlobFails(t *testing.T) {
	ring := testActiveRing(t)
	_, err := ring.Decrypt(context.Background(), &wrapping.BlobInfo{Ciphertext: []byte("x")}, nil)
	if !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("Decrypt error = %v, want ErrInvalidMetadata", err)
	}
}

func TestParseKeyRef(t *testing.T) {
	ref, err := ParseKeyRef("prod-eu1/root/v12")
	if err != nil {
		t.Fatalf("ParseKeyRef returned error: %v", err)
	}
	if ref.ClusterID != "prod-eu1" || ref.KeyID != "root" || ref.Version != 12 {
		t.Fatalf("ref = %#v, want prod-eu1/root/v12", ref)
	}
}

func TestCanonicalAADIsStable(t *testing.T) {
	version := testVersion(StatusActive, 1)
	aad, err := NewMetadata(version).CanonicalAAD([]byte("openbao aad"))
	if err != nil {
		t.Fatalf("CanonicalAAD returned error: %v", err)
	}
	wantParts := []string{
		`"schema_version":1`,
		`"purpose":"openbao-auto-unseal"`,
		`"cluster_id":"prod-eu1"`,
		`"key_id":"root"`,
		`"key_version":1`,
		`"algorithm":"AES-256-GCM"`,
		`"policy_id":"secureboot"`,
		`"blob_format":"openbao-attested-unseal.v1.aes256gcm"`,
		`"caller_aad":"b3BlbmJhbyBhYWQ="`,
	}
	for _, part := range wantParts {
		if !strings.Contains(string(aad), part) {
			t.Fatalf("AAD %q does not contain %q", aad, part)
		}
	}
}

func TestParseCanonicalAADRejectsOversizedMetadata(t *testing.T) {
	oversized := bytes.Repeat([]byte("x"), MaxAuthenticatedDataSize+1)
	if _, _, err := ParseCanonicalAAD(oversized); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("ParseCanonicalAAD error = %v, want ErrInvalidMetadata", err)
	}
}

func TestGoldenKeyringVectors(t *testing.T) {
	version := testVersion(StatusActive, 1)
	metadata := NewMetadata(version)

	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent returned error: %v", err)
	}
	assertGolden(t, "metadata.golden.json", append(metadataJSON, '\n'))

	aad, err := metadata.CanonicalAAD([]byte("openbao aad"))
	if err != nil {
		t.Fatalf("CanonicalAAD returned error: %v", err)
	}
	assertGolden(t, "aad.golden.json", append(aad, '\n'))

	assertGolden(t, "key-ref.golden.txt", []byte(version.Ref.String()+"\n"))
}

func TestGenerateKeyReturnsAES256Key(t *testing.T) {
	left, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	right, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	if len(left) != KeySize {
		t.Fatalf("key size = %d, want %d", len(left), KeySize)
	}
	if bytes.Equal(left, right) {
		t.Fatal("GenerateKey returned duplicate material")
	}
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	var want []byte
	var err error
	switch name {
	case "metadata.golden.json":
		want, err = os.ReadFile("testdata/metadata.golden.json")
	case "aad.golden.json":
		want, err = os.ReadFile("testdata/aad.golden.json")
	case "key-ref.golden.txt":
		want, err = os.ReadFile("testdata/key-ref.golden.txt")
	default:
		t.Fatalf("unknown golden file %q", name)
	}
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\nwant:\n%s\ngot:\n%s", name, want, got)
	}
}

func testActiveRing(t *testing.T) *Ring {
	t.Helper()
	ring, err := NewRing(testVersion(StatusActive, 1))
	if err != nil {
		t.Fatalf("NewRing returned error: %v", err)
	}
	return ring
}

func testVersion(status Status, version uint32) KeyVersion {
	seed := byte(1)
	if version == 2 {
		seed = 2
	}
	material := bytes.Repeat([]byte{seed}, KeySize)
	return KeyVersion{
		Ref: KeyRef{
			ClusterID: "prod-eu1",
			KeyID:     "root",
			Version:   version,
		},
		Status:    status,
		Algorithm: AlgorithmAES256GCM,
		PolicyID:  "secureboot",
		Material:  material,
	}
}
