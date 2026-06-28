// Package keyring implements local wrapping-key metadata and crypto primitives.
package keyring

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	// KeySize is the required AES-256 key size in bytes.
	KeySize = 32
	// NonceSize is the AES-GCM nonce size used by this package.
	NonceSize = 12
	// Purpose binds ciphertexts to OpenBao auto-unseal usage.
	Purpose = "openbao-auto-unseal"
	// BlobFormat identifies the authenticated ciphertext format.
	BlobFormat = "openbao-attested-unseal.v1.aes256gcm"
	// AlgorithmAES256GCM is the only local crypto algorithm in milestone 1.
	AlgorithmAES256GCM Algorithm = "AES-256-GCM"
	// BlobMechanismAES256GCM is stored in wrapping.KeyInfo.Mechanism.
	BlobMechanismAES256GCM uint64 = 1
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ErrInvalidMetadata indicates malformed key or blob metadata.
var ErrInvalidMetadata = errors.New("invalid key metadata")

// ErrKeyNotFound indicates a requested key version is not present.
var ErrKeyNotFound = errors.New("key version not found")

// ErrKeyNotUsable indicates a key exists but cannot perform the operation.
var ErrKeyNotUsable = errors.New("key version is not usable")

// Algorithm names a supported wrapping algorithm.
type Algorithm string

// KeyID identifies a cluster wrapping key independent of version.
type KeyID string

// Status is the local lifecycle status for one wrapping-key version.
type Status string

// KeyStatus is the design-facing alias for Status.
type KeyStatus = Status

const (
	// StatusPending is reserved for keys that exist but cannot be used yet.
	StatusPending Status = "pending"
	// StatusActive is the only status that may encrypt new blobs.
	StatusActive Status = "active"
	// StatusDecryptOnly may decrypt old blobs but cannot encrypt new blobs.
	StatusDecryptOnly Status = "decrypt-only"
	// StatusRetired cannot encrypt or decrypt.
	StatusRetired Status = "retired"
)

// KeyRef identifies one cluster wrapping-key version.
type KeyRef struct {
	ClusterID string
	KeyID     string
	Version   uint32
}

// Validate checks that the key reference can be safely encoded and parsed.
func (r KeyRef) Validate() error {
	if !validIdentifier(r.ClusterID) {
		return fmt.Errorf("%w: invalid cluster ID", ErrInvalidMetadata)
	}
	if !validIdentifier(r.KeyID) {
		return fmt.Errorf("%w: invalid key ID", ErrInvalidMetadata)
	}
	if r.Version == 0 {
		return fmt.Errorf("%w: key version must be greater than zero", ErrInvalidMetadata)
	}
	return nil
}

// String returns the stable BlobInfo key identifier format.
func (r KeyRef) String() string {
	return fmt.Sprintf("%s/%s/v%d", r.ClusterID, r.KeyID, r.Version)
}

// ParseKeyRef parses the stable BlobInfo key identifier format.
func ParseKeyRef(raw string) (KeyRef, error) {
	parts := strings.Split(raw, "/")
	if len(parts) != 3 {
		return KeyRef{}, fmt.Errorf("%w: malformed key reference", ErrInvalidMetadata)
	}
	if !strings.HasPrefix(parts[2], "v") {
		return KeyRef{}, fmt.Errorf("%w: malformed key version", ErrInvalidMetadata)
	}
	version, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "v"), 10, 32)
	if err != nil {
		return KeyRef{}, fmt.Errorf("%w: malformed key version", ErrInvalidMetadata)
	}
	ref := KeyRef{
		ClusterID: parts[0],
		KeyID:     parts[1],
		Version:   uint32(version),
	}
	if err := ref.Validate(); err != nil {
		return KeyRef{}, err
	}
	return ref, nil
}

// KeyVersion contains the metadata and key bytes for one wrapping-key version.
type KeyVersion struct {
	Ref       KeyRef
	Status    Status
	Algorithm Algorithm
	PolicyID  string
	Material  []byte
}

func (v KeyVersion) validate() error {
	if err := v.Ref.Validate(); err != nil {
		return err
	}
	switch v.Status {
	case StatusPending, StatusActive, StatusDecryptOnly, StatusRetired:
	default:
		return fmt.Errorf("%w: unknown key status", ErrInvalidMetadata)
	}
	if v.Algorithm != AlgorithmAES256GCM {
		return fmt.Errorf("%w: unsupported algorithm", ErrInvalidMetadata)
	}
	if !validIdentifier(v.PolicyID) {
		return fmt.Errorf("%w: invalid policy ID", ErrInvalidMetadata)
	}
	if len(v.Material) != KeySize {
		return fmt.Errorf("%w: key material must be %d bytes", ErrInvalidMetadata, KeySize)
	}
	return nil
}

func (v KeyVersion) clone() KeyVersion {
	v.Material = cloneBytes(v.Material)
	return v
}

func (v KeyVersion) canEncrypt() bool {
	return v.Status == StatusActive
}

func (v KeyVersion) canDecrypt() bool {
	return v.Status == StatusActive || v.Status == StatusDecryptOnly
}

// GenerateKey creates a random AES-256 wrapping key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate wrapping key: %w", err)
	}
	return key, nil
}

// ValidateIdentifier checks cluster, key, and policy identifiers.
func ValidateIdentifier(raw string) error {
	if !validIdentifier(raw) {
		return fmt.Errorf("%w: invalid identifier", ErrInvalidMetadata)
	}
	return nil
}

func validIdentifier(raw string) bool {
	return identifierPattern.MatchString(raw)
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
