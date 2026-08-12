// Package keyprotection defines the boundary between durable key records and
// unlocked wrapping-key capabilities.
package keyprotection

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

const (
	// ProfileDevelopment is the explicit local-lab key protection profile.
	ProfileDevelopment = "development"
	// FormatDevelopmentPlaintextV1 identifies intentionally unprotected development records.
	FormatDevelopmentPlaintextV1 = "openbao-attested-unseal.development-plaintext.v1"
)

var (
	// ErrInvalidProtectedKey indicates malformed protected key metadata or payload.
	ErrInvalidProtectedKey = errors.New("invalid protected key record")
	// ErrProtectorMismatch indicates a record cannot be opened by the selected protector.
	ErrProtectorMismatch = errors.New("key protector profile mismatch")
)

// ProtectedKey is the only wrapping-key representation that persistence may store.
type ProtectedKey struct {
	Ref              keyring.KeyRef
	Status           keyring.Status
	Algorithm        keyring.Algorithm
	PolicyID         string
	ProtectorProfile string
	Format           string
	Payload          []byte
}

// Validate checks durable metadata without interpreting the protected payload.
func (k ProtectedKey) Validate() error {
	if err := k.Ref.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProtectedKey, err)
	}
	switch k.Status {
	case keyring.StatusPending, keyring.StatusActive, keyring.StatusDecryptOnly, keyring.StatusRetired:
	default:
		return fmt.Errorf("%w: unsupported key status", ErrInvalidProtectedKey)
	}
	if k.Algorithm != keyring.AlgorithmAES256GCM {
		return fmt.Errorf("%w: unsupported key algorithm", ErrInvalidProtectedKey)
	}
	if err := keyring.ValidateIdentifier(k.PolicyID); err != nil {
		return fmt.Errorf("%w: invalid policy ID", ErrInvalidProtectedKey)
	}
	if err := keyring.ValidateIdentifier(k.ProtectorProfile); err != nil {
		return fmt.Errorf("%w: invalid protector profile", ErrInvalidProtectedKey)
	}
	if strings.TrimSpace(k.Format) == "" {
		return fmt.Errorf("%w: protected format is required", ErrInvalidProtectedKey)
	}
	if len(k.Payload) == 0 {
		return fmt.Errorf("%w: protected payload is required", ErrInvalidProtectedKey)
	}
	return nil
}

// Clone returns an independently owned protected record.
func (k ProtectedKey) Clone() ProtectedKey {
	k.Payload = slices.Clone(k.Payload)
	return k
}

// Metadata returns the non-secret key metadata represented by this record.
func (k ProtectedKey) Metadata() keyring.KeyVersion {
	return keyring.KeyVersion{
		Ref:       k.Ref,
		Status:    k.Status,
		Algorithm: k.Algorithm,
		PolicyID:  k.PolicyID,
	}
}

// Repository persists protected records without constructing unlocked keyrings.
type Repository interface {
	ProtectedKeys(context.Context, string) ([]ProtectedKey, error)
	ProtectedKey(context.Context, keyring.KeyRef) (ProtectedKey, error)
}

// Protector converts between one unlocked key version and its durable form.
type Protector interface {
	Profile() string
	Protect(context.Context, keyring.KeyVersion) (ProtectedKey, error)
	Unprotect(context.Context, ProtectedKey) (keyring.KeyVersion, error)
}

// KeyringProvider supplies a bounded unlocked capability to application services.
type KeyringProvider interface {
	LoadKeyring(context.Context, string) (*keyring.Ring, error)
}

// Loader opens protected repository records through one configured protector.
// It deliberately does not cache while legacy CLI rotation can still mutate
// state outside the running broker process.
type Loader struct {
	Repository Repository
	Protector  Protector
}

// LoadKeyring reconstructs a validated keyring from protected records.
func (l Loader) LoadKeyring(ctx context.Context, clusterID string) (*keyring.Ring, error) {
	if l.Repository == nil || l.Protector == nil {
		return nil, errors.New("key repository and protector are required")
	}
	records, err := l.Repository.ProtectedKeys(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	versions := make([]keyring.KeyVersion, 0, len(records))
	for _, record := range records {
		if record.ProtectorProfile != l.Protector.Profile() {
			return nil, fmt.Errorf(
				"%w: loader profile %q cannot open record profile %q",
				ErrProtectorMismatch,
				l.Protector.Profile(),
				record.ProtectorProfile,
			)
		}
		version, err := l.Protector.Unprotect(ctx, record)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return keyring.NewRing(versions...)
}
