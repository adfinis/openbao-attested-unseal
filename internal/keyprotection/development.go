package keyprotection

import (
	"context"
	"fmt"
	"slices"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

// DevelopmentProtector is an explicit plaintext adapter for tests and local labs.
// Its format name prevents stored bytes from being mistaken for production protection.
type DevelopmentProtector struct{}

// Profile returns the development-only profile identifier.
func (DevelopmentProtector) Profile() string {
	return ProfileDevelopment
}

// Protect labels and clones plaintext material for development persistence.
func (DevelopmentProtector) Protect(
	ctx context.Context,
	version keyring.KeyVersion,
) (ProtectedKey, error) {
	if err := ctx.Err(); err != nil {
		return ProtectedKey{}, err
	}
	if err := version.Validate(); err != nil {
		return ProtectedKey{}, err
	}
	record := ProtectedKey{
		Ref:              version.Ref,
		Status:           version.Status,
		Algorithm:        version.Algorithm,
		PolicyID:         version.PolicyID,
		ProtectorProfile: ProfileDevelopment,
		Format:           FormatDevelopmentPlaintextV1,
		Payload:          slices.Clone(version.Material),
	}
	if err := record.Validate(); err != nil {
		return ProtectedKey{}, err
	}
	return record, nil
}

// Unprotect opens only explicitly labelled development records.
func (DevelopmentProtector) Unprotect(
	ctx context.Context,
	record ProtectedKey,
) (keyring.KeyVersion, error) {
	if err := ctx.Err(); err != nil {
		return keyring.KeyVersion{}, err
	}
	if err := record.Validate(); err != nil {
		return keyring.KeyVersion{}, err
	}
	if record.ProtectorProfile != ProfileDevelopment || record.Format != FormatDevelopmentPlaintextV1 {
		return keyring.KeyVersion{}, fmt.Errorf(
			"%w: development protector cannot open profile %q format %q",
			ErrProtectorMismatch,
			record.ProtectorProfile,
			record.Format,
		)
	}
	version := record.Metadata()
	version.Material = slices.Clone(record.Payload)
	if err := version.Validate(); err != nil {
		return keyring.KeyVersion{}, err
	}
	return version, nil
}
