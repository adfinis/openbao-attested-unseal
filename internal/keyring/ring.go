package keyring

import (
	"context"
	"fmt"
)

// Ring selects active and historical wrapping-key versions.
type Ring struct {
	versions []KeyVersion
}

// NewRing validates and copies the supplied key versions.
func NewRing(versions ...KeyVersion) (*Ring, error) {
	if len(versions) == 0 {
		return nil, fmt.Errorf("%w: at least one key version is required", ErrInvalidMetadata)
	}

	copied := make([]KeyVersion, 0, len(versions))
	activeCount := 0
	for _, version := range versions {
		if err := version.validate(); err != nil {
			return nil, err
		}
		if containsRef(copied, version.Ref) {
			return nil, fmt.Errorf("%w: duplicate key reference", ErrInvalidMetadata)
		}
		if version.Status == StatusActive {
			activeCount++
		}
		copied = append(copied, version.clone())
	}
	if activeCount != 1 {
		return nil, fmt.Errorf("%w: exactly one active key version is required", ErrInvalidMetadata)
	}

	return &Ring{versions: copied}, nil
}

// Active returns the active key version used for new encryption.
func (r *Ring) Active(_ context.Context) (KeyVersion, error) {
	if r == nil {
		return KeyVersion{}, fmt.Errorf("%w: nil keyring", ErrInvalidMetadata)
	}
	for _, version := range r.versions {
		if version.canEncrypt() {
			return version.clone(), nil
		}
	}
	return KeyVersion{}, ErrKeyNotUsable
}

func (r *Ring) keyForDecrypt(ref KeyRef) (KeyVersion, error) {
	if r == nil {
		return KeyVersion{}, fmt.Errorf("%w: nil keyring", ErrInvalidMetadata)
	}
	for _, version := range r.versions {
		if sameRef(version.Ref, ref) {
			if !version.canDecrypt() {
				return KeyVersion{}, ErrKeyNotUsable
			}
			return version.clone(), nil
		}
	}
	return KeyVersion{}, ErrKeyNotFound
}

func containsRef(versions []KeyVersion, ref KeyRef) bool {
	for _, version := range versions {
		if sameRef(version.Ref, ref) {
			return true
		}
	}
	return false
}

func sameRef(left KeyRef, right KeyRef) bool {
	return left.ClusterID == right.ClusterID && left.KeyID == right.KeyID && left.Version == right.Version
}
