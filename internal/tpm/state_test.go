package tpm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

func TestLocalStateStatusWarnsRevocationRequiresRotation(t *testing.T) {
	ref := keyring.KeyRef{ClusterID: "prod", KeyID: "root", Version: 1}
	statePath := t.TempDir()
	sealed := SealedBlob{
		SchemaVersion: SealedBlobSchemaVersion,
		PolicyMode:    PolicyModeTPMOnly,
		Public:        []byte("public"),
		Private:       []byte("private"),
	}
	metadata := LocalKeyMetadata{
		SchemaVersion:    LocalStateSchemaVersion,
		ClusterID:        ref.ClusterID,
		KeyID:            ref.KeyID,
		Version:          ref.Version,
		Status:           string(keyring.StatusActive),
		Algorithm:        string(keyring.AlgorithmAES256GCM),
		PolicyID:         "policy",
		TPMPolicy:        Policy{Mode: PolicyModeTPMOnly},
		RevocationNotice: RevocationWarning,
	}
	if err := writeLocalState(statePath, ref, sealed, metadata); err != nil {
		t.Fatalf("writeLocalState returned error: %v", err)
	}
	status := StatusLocal(statePath, ref)
	if !status.Ready {
		t.Fatalf("Ready = false, errors = %v", status.Errors)
	}
	if len(status.Warnings) != 1 || status.Warnings[0] != RevocationWarning {
		t.Fatalf("warnings = %v, want %q", status.Warnings, RevocationWarning)
	}
}

func TestReadLocalStateRejectsClusterMismatch(t *testing.T) {
	ref := keyring.KeyRef{ClusterID: "prod", KeyID: "root", Version: 1}
	statePath := t.TempDir()
	sealed := SealedBlob{
		SchemaVersion: SealedBlobSchemaVersion,
		PolicyMode:    PolicyModeTPMOnly,
		Public:        []byte("public"),
		Private:       []byte("private"),
	}
	metadata := LocalKeyMetadata{
		SchemaVersion:    LocalStateSchemaVersion,
		ClusterID:        "other",
		KeyID:            ref.KeyID,
		Version:          ref.Version,
		Status:           string(keyring.StatusActive),
		Algorithm:        string(keyring.AlgorithmAES256GCM),
		PolicyID:         "policy",
		TPMPolicy:        Policy{Mode: PolicyModeTPMOnly},
		RevocationNotice: RevocationWarning,
	}
	if err := writeLocalStateUnchecked(statePath, ref, sealed, metadata); err != nil {
		t.Fatalf("writeLocalStateUnchecked returned error: %v", err)
	}
	_, _, err := ReadLocalState(statePath, ref)
	if !errors.Is(err, keyring.ErrInvalidMetadata) {
		t.Fatalf("ReadLocalState error = %v, want ErrInvalidMetadata", err)
	}
}

func TestReadLocalStateRejectsUnsafePermissions(t *testing.T) {
	ref := keyring.KeyRef{ClusterID: "prod", KeyID: "root", Version: 1}
	statePath := t.TempDir()
	sealed := SealedBlob{
		SchemaVersion: SealedBlobSchemaVersion,
		PolicyMode:    PolicyModeTPMOnly,
		Public:        []byte("public"),
		Private:       []byte("private"),
	}
	metadata := LocalKeyMetadata{
		SchemaVersion:    LocalStateSchemaVersion,
		ClusterID:        ref.ClusterID,
		KeyID:            ref.KeyID,
		Version:          ref.Version,
		Status:           string(keyring.StatusActive),
		Algorithm:        string(keyring.AlgorithmAES256GCM),
		PolicyID:         "policy",
		TPMPolicy:        Policy{Mode: PolicyModeTPMOnly},
		RevocationNotice: RevocationWarning,
	}
	if err := writeLocalState(statePath, ref, sealed, metadata); err != nil {
		t.Fatalf("writeLocalState returned error: %v", err)
	}
	paths, err := localKeyPaths(statePath, ref)
	if err != nil {
		t.Fatalf("localKeyPaths returned error: %v", err)
	}
	//nolint:gosec // Test intentionally creates unsafe permissions.
	if err := os.Chmod(paths.metadata, 0o644); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	_, _, err = ReadLocalState(statePath, ref)
	if !errors.Is(err, keyring.ErrInvalidMetadata) {
		t.Fatalf("ReadLocalState error = %v, want ErrInvalidMetadata", err)
	}
}

func writeLocalStateUnchecked(
	statePath string,
	ref keyring.KeyRef,
	sealed SealedBlob,
	metadata LocalKeyMetadata,
) error {
	if err := os.MkdirAll(filepath.Join(statePath, LocalStateDir, "keys", ref.KeyID), 0o700); err != nil {
		return err
	}
	paths, err := localKeyPaths(statePath, ref)
	if err != nil {
		return err
	}
	for path, value := range map[string]any{
		paths.sealed:   sealed,
		paths.metadata: metadata,
	} {
		payload, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			return err
		}
	}
	return nil
}
