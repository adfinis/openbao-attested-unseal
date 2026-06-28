package tpm

import (
	"fmt"
	"io"
	"time"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	SealedBlobSchemaVersion uint32 = 1
	sealedObjectAuth               = ""
)

// SealedBlob stores a TPM2 sealed object under the deterministic owner SRK.
type SealedBlob struct {
	SchemaVersion uint32     `json:"schema_version"`
	PolicyMode    string     `json:"policy_mode"`
	Public        []byte     `json:"public"`
	Private       []byte     `json:"private"`
	PCRPolicy     *PCRPolicy `json:"pcr_policy,omitempty"`
	CreatedAtUTC  string     `json:"created_at_utc"`
}

// SealKey seals key material into the local TPM.
func SealKey(rw io.ReadWriter, plaintext []byte, mode string, selection PCRSelection) (SealedBlob, error) {
	if rw == nil {
		return SealedBlob{}, fmt.Errorf("TPM connection is required")
	}
	if len(plaintext) == 0 {
		return SealedBlob{}, fmt.Errorf("plaintext is required")
	}
	srkHandle, err := createSRK(rw)
	if err != nil {
		return SealedBlob{}, err
	}
	defer func() {
		_ = legacytpm2.FlushContext(rw, srkHandle)
	}()

	var (
		policyDigest []byte
		pcrPolicy    *PCRPolicy
	)
	switch mode {
	case PolicyModeTPMOnly:
		session, digest, err := policySession(rw, nil)
		if err != nil {
			return SealedBlob{}, err
		}
		_ = legacytpm2.FlushContext(rw, session)
		policyDigest = digest
	case PolicyModeSecureBoot:
		normalized, err := selection.Normalize()
		if err != nil {
			return SealedBlob{}, err
		}
		if !normalized.contains(7) {
			return SealedBlob{}, fmt.Errorf("%w: secureboot seal requires PCR 7", ErrAttestationPolicy)
		}
		session, digest, err := policySession(rw, &normalized)
		if err != nil {
			return SealedBlob{}, err
		}
		_ = legacytpm2.FlushContext(rw, session)
		values, err := readPCRValues(rw, normalized)
		if err != nil {
			return SealedBlob{}, err
		}
		policy, err := NewPCRPolicy(normalized, values, ProfileGenericPCSecureBoot)
		if err != nil {
			return SealedBlob{}, err
		}
		policyDigest = digest
		pcrPolicy = &policy
	case PolicyModeMeasured:
		return SealedBlob{}, fmt.Errorf("%w: measured mode is not implemented", ErrAttestationPolicy)
	default:
		return SealedBlob{}, fmt.Errorf("%w: unsupported policy mode %q", ErrAttestationPolicy, mode)
	}

	privateBlob, publicBlob, err := legacytpm2.Seal(
		rw,
		srkHandle,
		"",
		sealedObjectAuth,
		policyDigest,
		plaintext,
	)
	if err != nil {
		return SealedBlob{}, fmt.Errorf("seal key material: %w", err)
	}
	blob := SealedBlob{
		SchemaVersion: SealedBlobSchemaVersion,
		PolicyMode:    mode,
		Public:        publicBlob,
		Private:       privateBlob,
		PCRPolicy:     pcrPolicy,
		CreatedAtUTC:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := blob.Validate(); err != nil {
		return SealedBlob{}, err
	}
	return blob, nil
}

// UnsealKey unseals key material through the local TPM.
func UnsealKey(rw io.ReadWriter, blob SealedBlob) ([]byte, error) {
	if rw == nil {
		return nil, fmt.Errorf("TPM connection is required")
	}
	if err := blob.Validate(); err != nil {
		return nil, err
	}
	srkHandle, err := createSRK(rw)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = legacytpm2.FlushContext(rw, srkHandle)
	}()
	objectHandle, _, err := legacytpm2.Load(rw, srkHandle, "", blob.Public, blob.Private)
	if err != nil {
		return nil, fmt.Errorf("load sealed object: %w", err)
	}
	defer func() {
		_ = legacytpm2.FlushContext(rw, objectHandle)
	}()

	var selection *PCRSelection
	if blob.PolicyMode == PolicyModeSecureBoot {
		selection = &blob.PCRPolicy.Selection
	}
	session, _, err := policySession(rw, selection)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = legacytpm2.FlushContext(rw, session)
	}()
	plaintext, err := legacytpm2.UnsealWithSession(rw, session, objectHandle, sealedObjectAuth)
	if err != nil {
		return nil, fmt.Errorf("unseal key material: %w", err)
	}
	return plaintext, nil
}

// Validate checks sealed object shape.
func (b SealedBlob) Validate() error {
	if b.SchemaVersion != SealedBlobSchemaVersion {
		return fmt.Errorf("unsupported sealed blob schema version")
	}
	if len(b.Public) == 0 || len(b.Private) == 0 {
		return fmt.Errorf("sealed object public and private blobs are required")
	}
	switch b.PolicyMode {
	case PolicyModeTPMOnly:
		if b.PCRPolicy != nil {
			return fmt.Errorf("%w: tpm-only sealed object must not contain PCR policy", ErrAttestationPolicy)
		}
	case PolicyModeSecureBoot:
		if b.PCRPolicy == nil {
			return fmt.Errorf("%w: secureboot sealed object requires PCR policy", ErrAttestationPolicy)
		}
		if err := b.PCRPolicy.Validate(); err != nil {
			return err
		}
	case PolicyModeMeasured:
		return fmt.Errorf("%w: measured mode is not implemented", ErrAttestationPolicy)
	default:
		return fmt.Errorf("%w: unsupported policy mode %q", ErrAttestationPolicy, b.PolicyMode)
	}
	return nil
}

func createSRK(rw io.ReadWriter) (tpmutil.Handle, error) {
	handle, _, err := legacytpm2.CreatePrimary(
		rw,
		legacytpm2.HandleOwner,
		legacytpm2.PCRSelection{},
		"",
		"",
		srkTemplate(),
	)
	if err != nil {
		return 0, fmt.Errorf("create SRK: %w", err)
	}
	return handle, nil
}

func srkTemplate() legacytpm2.Public {
	return legacytpm2.Public{
		Type:    legacytpm2.AlgRSA,
		NameAlg: legacytpm2.AlgSHA256,
		Attributes: legacytpm2.FlagFixedTPM |
			legacytpm2.FlagFixedParent |
			legacytpm2.FlagSensitiveDataOrigin |
			legacytpm2.FlagUserWithAuth |
			legacytpm2.FlagRestricted |
			legacytpm2.FlagDecrypt |
			legacytpm2.FlagNoDA,
		RSAParameters: &legacytpm2.RSAParams{
			Symmetric: &legacytpm2.SymScheme{
				Alg:     legacytpm2.AlgAES,
				KeyBits: 128,
				Mode:    legacytpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
}

func policySession(rw io.ReadWriter, selection *PCRSelection) (tpmutil.Handle, []byte, error) {
	session, _, err := legacytpm2.StartAuthSession(
		rw,
		legacytpm2.HandleNull,
		legacytpm2.HandleNull,
		make([]byte, 16),
		nil,
		legacytpm2.SessionPolicy,
		legacytpm2.AlgNull,
		legacytpm2.AlgSHA256,
	)
	if err != nil {
		return 0, nil, fmt.Errorf("start policy session: %w", err)
	}
	if selection != nil {
		legacySelection, err := selection.legacy()
		if err != nil {
			_ = legacytpm2.FlushContext(rw, session)
			return 0, nil, err
		}
		if err := legacytpm2.PolicyPCR(rw, session, nil, legacySelection); err != nil {
			_ = legacytpm2.FlushContext(rw, session)
			return 0, nil, fmt.Errorf("bind PCR policy: %w", err)
		}
	}
	if err := legacytpm2.PolicyPassword(rw, session); err != nil {
		_ = legacytpm2.FlushContext(rw, session)
		return 0, nil, fmt.Errorf("bind password policy: %w", err)
	}
	digest, err := legacytpm2.PolicyGetDigest(rw, session)
	if err != nil {
		_ = legacytpm2.FlushContext(rw, session)
		return 0, nil, fmt.Errorf("read policy digest: %w", err)
	}
	return session, digest, nil
}

func readPCRValues(rw io.ReadWriter, selection PCRSelection) (map[int][]byte, error) {
	legacySelection, err := selection.legacy()
	if err != nil {
		return nil, err
	}
	values, err := legacytpm2.ReadPCRs(rw, legacySelection)
	if err != nil {
		return nil, fmt.Errorf("read PCR values: %w", err)
	}
	return values, nil
}
