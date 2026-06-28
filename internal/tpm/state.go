package tpm

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

const (
	LocalStateSchemaVersion uint32 = 1
	LocalStateDir                  = "local-tpm"
	RevocationWarning              = "local TPM revocation requires key rotation"
)

// LocalKeyMetadata describes one locally sealed wrapping-key version.
type LocalKeyMetadata struct {
	SchemaVersion    uint32     `json:"schema_version"`
	ClusterID        string     `json:"cluster_id"`
	KeyID            string     `json:"key_id"`
	Version          uint32     `json:"version"`
	Status           string     `json:"status"`
	Algorithm        string     `json:"algorithm"`
	PolicyID         string     `json:"policy_id"`
	TPMPolicy        Policy     `json:"tpm_policy"`
	RevocationNotice string     `json:"revocation_notice"`
	CreatedAtUTC     string     `json:"created_at_utc"`
	PCRPolicy        *PCRPolicy `json:"pcr_policy,omitempty"`
}

// LocalStatus reports local TPM state without exposing key material.
type LocalStatus struct {
	Ready    bool
	Key      keyring.KeyRef
	Mode     string
	Warnings []string
	Errors   []string
}

// StoreLocalKey seals and writes one local TPM key version.
func StoreLocalKey(
	ctx context.Context,
	statePath string,
	device Device,
	version keyring.KeyVersion,
	mode string,
	selection PCRSelection,
) (LocalKeyMetadata, error) {
	if err := ctx.Err(); err != nil {
		return LocalKeyMetadata{}, err
	}
	if err := version.Ref.Validate(); err != nil {
		return LocalKeyMetadata{}, err
	}
	if len(version.Material) != keyring.KeySize {
		return LocalKeyMetadata{}, fmt.Errorf(
			"%w: key material must be %d bytes",
			keyring.ErrInvalidMetadata,
			keyring.KeySize,
		)
	}
	rwc, err := device.Open(ctx)
	if err != nil {
		return LocalKeyMetadata{}, err
	}
	defer func() {
		_ = rwc.Close()
	}()
	sealed, err := SealKey(rwc, version.Material, mode, selection)
	if err != nil {
		return LocalKeyMetadata{}, err
	}
	unsealed, err := UnsealKey(rwc, sealed)
	if err != nil {
		return LocalKeyMetadata{}, fmt.Errorf("verify local TPM sealed key: %w", err)
	}
	if subtle.ConstantTimeCompare(unsealed, version.Material) != 1 {
		return LocalKeyMetadata{}, fmt.Errorf("%w: local TPM sealed key verification failed", keyring.ErrInvalidMetadata)
	}
	policy := Policy{
		Mode:            mode,
		PCRPolicy:       sealed.PCRPolicy,
		ProviderProfile: profileForMode(mode),
	}
	metadata := LocalKeyMetadata{
		SchemaVersion:    LocalStateSchemaVersion,
		ClusterID:        version.Ref.ClusterID,
		KeyID:            version.Ref.KeyID,
		Version:          version.Ref.Version,
		Status:           string(version.Status),
		Algorithm:        string(version.Algorithm),
		PolicyID:         version.PolicyID,
		TPMPolicy:        policy,
		RevocationNotice: RevocationWarning,
		CreatedAtUTC:     time.Now().UTC().Format(time.RFC3339Nano),
		PCRPolicy:        sealed.PCRPolicy,
	}
	if err := metadata.Validate(version.Ref); err != nil {
		return LocalKeyMetadata{}, err
	}
	if err := writeLocalState(statePath, version.Ref, sealed, metadata); err != nil {
		return LocalKeyMetadata{}, err
	}
	return metadata, nil
}

// LoadLocalRing unseals local TPM state and returns a keyring for AEAD operations.
func LoadLocalRing(
	ctx context.Context,
	statePath string,
	device Device,
	ref keyring.KeyRef,
) (*keyring.Ring, LocalKeyMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, LocalKeyMetadata{}, err
	}
	sealed, metadata, err := ReadLocalState(statePath, ref)
	if err != nil {
		return nil, LocalKeyMetadata{}, err
	}
	rwc, err := device.Open(ctx)
	if err != nil {
		return nil, LocalKeyMetadata{}, err
	}
	defer func() {
		_ = rwc.Close()
	}()
	material, err := UnsealKey(rwc, sealed)
	if err != nil {
		return nil, LocalKeyMetadata{}, err
	}
	version := keyring.KeyVersion{
		Ref:       ref,
		Status:    keyring.Status(metadata.Status),
		Algorithm: keyring.Algorithm(metadata.Algorithm),
		PolicyID:  metadata.PolicyID,
		Material:  material,
	}
	ring, err := keyring.NewRing(version)
	if err != nil {
		return nil, LocalKeyMetadata{}, err
	}
	return ring, metadata, nil
}

// ReadLocalState reads and validates local TPM metadata and sealed object state.
func ReadLocalState(statePath string, ref keyring.KeyRef) (SealedBlob, LocalKeyMetadata, error) {
	if err := validateStateRoot(statePath); err != nil {
		return SealedBlob{}, LocalKeyMetadata{}, err
	}
	paths, err := localKeyPaths(statePath, ref)
	if err != nil {
		return SealedBlob{}, LocalKeyMetadata{}, err
	}
	metadata, err := readLocalKeyMetadata(paths.metadata)
	if err != nil {
		return SealedBlob{}, LocalKeyMetadata{}, err
	}
	if err := metadata.Validate(ref); err != nil {
		return SealedBlob{}, LocalKeyMetadata{}, err
	}
	sealed, err := readSealedBlob(paths.sealed)
	if err != nil {
		return SealedBlob{}, LocalKeyMetadata{}, err
	}
	if err := sealed.Validate(); err != nil {
		return SealedBlob{}, LocalKeyMetadata{}, err
	}
	return sealed, metadata, nil
}

// StatusLocal reports local TPM metadata readiness without unsealing key material.
func StatusLocal(statePath string, ref keyring.KeyRef) LocalStatus {
	_, metadata, err := ReadLocalState(statePath, ref)
	if err != nil {
		return LocalStatus{Ready: false, Key: ref, Warnings: []string{RevocationWarning}, Errors: []string{err.Error()}}
	}
	return LocalStatus{
		Ready:    true,
		Key:      ref,
		Mode:     metadata.TPMPolicy.Mode,
		Warnings: []string{RevocationWarning},
	}
}

// Validate checks metadata against the expected key reference.
func (m LocalKeyMetadata) Validate(ref keyring.KeyRef) error {
	if m.SchemaVersion != LocalStateSchemaVersion {
		return fmt.Errorf("%w: unsupported local state schema version", keyring.ErrInvalidMetadata)
	}
	if m.ClusterID != ref.ClusterID || m.KeyID != ref.KeyID || m.Version != ref.Version {
		return fmt.Errorf("%w: local TPM metadata key reference mismatch", keyring.ErrInvalidMetadata)
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if m.Algorithm != string(keyring.AlgorithmAES256GCM) {
		return fmt.Errorf("%w: unsupported local key algorithm", keyring.ErrInvalidMetadata)
	}
	switch keyring.Status(m.Status) {
	case keyring.StatusActive, keyring.StatusDecryptOnly, keyring.StatusPending, keyring.StatusRetired:
	default:
		return fmt.Errorf("%w: unsupported local key status", keyring.ErrInvalidMetadata)
	}
	if err := keyring.ValidateIdentifier(m.PolicyID); err != nil {
		return err
	}
	if m.RevocationNotice != RevocationWarning {
		return fmt.Errorf("%w: missing local TPM revocation notice", keyring.ErrInvalidMetadata)
	}
	if err := m.TPMPolicy.Validate(); err != nil {
		return err
	}
	return nil
}

type keyPaths struct {
	dir      string
	sealed   string
	metadata string
	pcr      string
}

func writeLocalState(statePath string, ref keyring.KeyRef, sealed SealedBlob, metadata LocalKeyMetadata) error {
	if err := ensureStateRoot(statePath); err != nil {
		return err
	}
	paths, err := localKeyPaths(statePath, ref)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.dir, 0o700); err != nil {
		return fmt.Errorf("create local TPM key directory: %w", err)
	}
	if err := writeSealedBlob(paths.sealed, sealed, 0o600); err != nil {
		return err
	}
	if err := writeLocalKeyMetadata(paths.metadata, metadata, 0o600); err != nil {
		return err
	}
	if sealed.PCRPolicy != nil {
		if err := writePCRPolicy(paths.pcr, *sealed.PCRPolicy, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func ensureStateRoot(statePath string) error {
	if strings.TrimSpace(statePath) == "" {
		return fmt.Errorf("%w: state path is required", keyring.ErrInvalidMetadata)
	}
	if err := os.MkdirAll(filepath.Join(statePath, LocalStateDir, "keys"), 0o700); err != nil {
		return fmt.Errorf("create local TPM state path: %w", err)
	}
	return validateStateRoot(statePath)
}

func validateStateRoot(statePath string) error {
	if strings.TrimSpace(statePath) == "" {
		return fmt.Errorf("%w: state path is required", keyring.ErrInvalidMetadata)
	}
	for _, path := range []string{
		statePath,
		filepath.Join(statePath, LocalStateDir),
		filepath.Join(statePath, LocalStateDir, "keys"),
	} {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect local TPM state path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: local TPM state path must not contain symlinks", keyring.ErrInvalidMetadata)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: local TPM state path component is not a directory", keyring.ErrInvalidMetadata)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%w: local TPM state path must not be group/world writable", keyring.ErrInvalidMetadata)
		}
	}
	return nil
}

func localKeyPaths(statePath string, ref keyring.KeyRef) (keyPaths, error) {
	if err := ref.Validate(); err != nil {
		return keyPaths{}, err
	}
	version := "v" + strconv.FormatUint(uint64(ref.Version), 10)
	keyDir := filepath.Join(statePath, LocalStateDir, "keys", ref.KeyID)
	return keyPaths{
		dir:      keyDir,
		sealed:   filepath.Join(keyDir, version+".sealed"),
		metadata: filepath.Join(keyDir, version+".metadata.json"),
		pcr:      filepath.Join(keyDir, "pcr-policy.json"),
	}, nil
}

func readSealedBlob(path string) (SealedBlob, error) {
	var out SealedBlob
	if err := readLocalJSON(path, &out); err != nil {
		return SealedBlob{}, err
	}
	return out, nil
}

func readLocalKeyMetadata(path string) (LocalKeyMetadata, error) {
	var out LocalKeyMetadata
	if err := readLocalJSON(path, &out); err != nil {
		return LocalKeyMetadata{}, err
	}
	return out, nil
}

func readLocalJSON(path string, out interface{}) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s must not be a symlink", keyring.ErrInvalidMetadata, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s must not be group/world accessible", keyring.ErrInvalidMetadata, path)
	}
	payload, err := os.ReadFile(path) //nolint:gosec // Path is local state validated above for symlinks and permissions.
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func writeSealedBlob(path string, value SealedBlob, perm os.FileMode) error {
	return writeLocalJSON(path, value, perm)
}

func writeLocalKeyMetadata(path string, value LocalKeyMetadata, perm os.FileMode) error {
	return writeLocalJSON(path, value, perm)
}

func writePCRPolicy(path string, value PCRPolicy, perm os.FileMode) error {
	return writeLocalJSON(path, value, perm)
}

func writeLocalJSON(path string, value interface{}, perm os.FileMode) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, perm); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func profileForMode(mode string) string {
	if mode == PolicyModeSecureBoot {
		return ProfileGenericPCSecureBoot
	}
	return ""
}
