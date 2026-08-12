package keyprotection

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

func TestDevelopmentProtectorRoundTripIsExplicitlyPlaintext(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{0x42}, keyring.KeySize)
	version := testVersion(material)
	protector := DevelopmentProtector{}

	record, err := protector.Protect(context.Background(), version)
	if err != nil {
		t.Fatalf("Protect returned error: %v", err)
	}
	if record.ProtectorProfile != ProfileDevelopment || record.Format != FormatDevelopmentPlaintextV1 {
		t.Fatalf("protected record labels = %q %q", record.ProtectorProfile, record.Format)
	}
	if !bytes.Equal(record.Payload, material) {
		t.Fatal("development record payload differs from plaintext material")
	}
	material[0] ^= 0xff
	if record.Payload[0] == material[0] {
		t.Fatal("Protect retained caller-owned material")
	}

	opened, err := protector.Unprotect(context.Background(), record)
	if err != nil {
		t.Fatalf("Unprotect returned error: %v", err)
	}
	if !bytes.Equal(opened.Material, record.Payload) {
		t.Fatal("opened material differs from protected development payload")
	}
}

func TestDevelopmentProtectorRejectsAnotherProfile(t *testing.T) {
	t.Parallel()
	record, err := (DevelopmentProtector{}).Protect(
		context.Background(),
		testVersion(bytes.Repeat([]byte{0x24}, keyring.KeySize)),
	)
	if err != nil {
		t.Fatalf("Protect returned error: %v", err)
	}
	record.ProtectorProfile = "broker-tpm"
	_, err = (DevelopmentProtector{}).Unprotect(context.Background(), record)
	if !errors.Is(err, ErrProtectorMismatch) {
		t.Fatalf("Unprotect error = %v, want ErrProtectorMismatch", err)
	}
}

func TestLoaderReconstructsKeyringThroughProtector(t *testing.T) {
	t.Parallel()
	record, err := (DevelopmentProtector{}).Protect(
		context.Background(),
		testVersion(bytes.Repeat([]byte{0x36}, keyring.KeySize)),
	)
	if err != nil {
		t.Fatalf("Protect returned error: %v", err)
	}
	loader := Loader{
		Repository: staticRepository{records: []ProtectedKey{record}},
		Protector:  DevelopmentProtector{},
	}
	ring, err := loader.LoadKeyring(context.Background(), record.Ref.ClusterID)
	if err != nil {
		t.Fatalf("LoadKeyring returned error: %v", err)
	}
	active, err := ring.Active(context.Background())
	if err != nil {
		t.Fatalf("Active returned error: %v", err)
	}
	if active.Ref != record.Ref || !bytes.Equal(active.Material, record.Payload) {
		t.Fatalf("active key = %#v, want protected record metadata and payload", active)
	}
}

type staticRepository struct {
	records []ProtectedKey
}

func (r staticRepository) ProtectedKeys(context.Context, string) ([]ProtectedKey, error) {
	return r.records, nil
}

func (r staticRepository) ProtectedKey(_ context.Context, ref keyring.KeyRef) (ProtectedKey, error) {
	for _, record := range r.records {
		if record.Ref == ref {
			return record, nil
		}
	}
	return ProtectedKey{}, keyring.ErrKeyNotFound
}

func testVersion(material []byte) keyring.KeyVersion {
	return keyring.KeyVersion{
		Ref: keyring.KeyRef{
			ClusterID: "prod-eu1",
			KeyID:     "root",
			Version:   1,
		},
		Status:    keyring.StatusActive,
		Algorithm: keyring.AlgorithmAES256GCM,
		PolicyID:  "development",
		Material:  material,
	}
}
