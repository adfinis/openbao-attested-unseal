package tpm

import (
	"crypto/subtle"
	"fmt"
	"strings"
)

const (
	PolicyModeTPMOnly    = "tpm-only"
	PolicyModeSecureBoot = "secureboot"
	PolicyModeMeasured   = "measured"

	ProfileGenericPCSecureBoot = "generic-pc-secureboot"
)

// Policy describes the enrolled TPM identity and boot-state requirements.
type Policy struct {
	Mode                 string     `json:"mode"`
	EnrolledAKPublicHash string     `json:"enrolled_ak_public_hash"`
	PCRPolicy            *PCRPolicy `json:"pcr_policy,omitempty"`
	ProviderProfile      string     `json:"provider_profile,omitempty"`
}

// Claims are normalized facts consumed by provider adapters or policy code.
type Claims struct {
	SubjectFingerprint string
	AKPublicHash       string
	PCRSelection       PCRSelection
	PCRDigest          string
	SecureBoot         bool
	Fresh              bool
	PolicyMode         string
	ProviderProfile    string
}

// EvaluatePolicy verifies quote evidence against an enrolled TPM policy.
func EvaluatePolicy(evidence Evidence, expectedNonce []byte, policy Policy) (Claims, error) {
	if err := policy.Validate(); err != nil {
		return Claims{}, err
	}
	quoteClaims, err := VerifyQuote(evidence, expectedNonce)
	if err != nil {
		return Claims{}, err
	}
	if policy.EnrolledAKPublicHash != "" &&
		subtle.ConstantTimeCompare([]byte(policy.EnrolledAKPublicHash), []byte(quoteClaims.AKPublicHash)) != 1 {
		return Claims{}, fmt.Errorf("%w: AK public hash mismatch", ErrAttestationPolicy)
	}
	claims := Claims{
		SubjectFingerprint: quoteClaims.AKPublicHash,
		AKPublicHash:       quoteClaims.AKPublicHash,
		PCRSelection:       quoteClaims.PCRSelection,
		PCRDigest:          quoteClaims.PCRDigest,
		Fresh:              true,
		PolicyMode:         policy.Mode,
		ProviderProfile:    policy.ProviderProfile,
	}
	switch policy.Mode {
	case PolicyModeTPMOnly:
		return claims, nil
	case PolicyModeSecureBoot:
		if err := verifySecureBootPolicy(quoteClaims, policy); err != nil {
			return Claims{}, err
		}
		claims.SecureBoot = true
		return claims, nil
	case PolicyModeMeasured:
		return Claims{}, fmt.Errorf("%w: measured mode requires policy-update flow", ErrAttestationPolicy)
	default:
		return Claims{}, fmt.Errorf("%w: unsupported policy mode %q", ErrAttestationPolicy, policy.Mode)
	}
}

// Validate checks a policy for structural safety.
func (p Policy) Validate() error {
	mode := strings.TrimSpace(p.Mode)
	switch mode {
	case PolicyModeTPMOnly, PolicyModeSecureBoot, PolicyModeMeasured:
	default:
		return fmt.Errorf("%w: unsupported policy mode %q", ErrAttestationPolicy, p.Mode)
	}
	if p.EnrolledAKPublicHash != "" {
		hashName, digest, err := parseDigestString(p.EnrolledAKPublicHash)
		if err != nil || hashName != HashSHA256 || len(digest) != 32 {
			return fmt.Errorf("%w: enrolled AK public hash must be sha256:hex", ErrAttestationPolicy)
		}
	}
	if mode == PolicyModeSecureBoot {
		if p.ProviderProfile == "" {
			return fmt.Errorf("%w: secureboot profile is required", ErrAttestationPolicy)
		}
		if p.ProviderProfile != ProfileGenericPCSecureBoot {
			return fmt.Errorf("%w: %s", ErrUnsupportedProfile, p.ProviderProfile)
		}
		if p.PCRPolicy == nil {
			return fmt.Errorf("%w: PCR policy is required for secureboot", ErrAttestationPolicy)
		}
		if err := p.PCRPolicy.Validate(); err != nil {
			return err
		}
		if !p.PCRPolicy.Selection.contains(7) {
			return fmt.Errorf("%w: generic secureboot profile requires PCR 7", ErrAttestationPolicy)
		}
	}
	return nil
}

// Validate checks PCR policy shape.
func (p PCRPolicy) Validate() error {
	selection, err := p.Selection.Normalize()
	if err != nil {
		return fmt.Errorf("%w: invalid PCR policy selection: %v", ErrAttestationPolicy, err)
	}
	hash, digest, err := parseDigestString(p.ExpectedDigest)
	if err != nil {
		return fmt.Errorf("%w: invalid PCR policy digest: %v", ErrAttestationPolicy, err)
	}
	if hash != selection.Hash {
		return fmt.Errorf("%w: PCR policy digest hash mismatch", ErrAttestationPolicy)
	}
	size, err := hashDigestSize(hash)
	if err != nil {
		return err
	}
	if len(digest) != size {
		return fmt.Errorf("%w: PCR policy digest size = %d, want %d", ErrAttestationPolicy, len(digest), size)
	}
	return nil
}

func verifySecureBootPolicy(claims QuoteClaims, policy Policy) error {
	expected := policy.PCRPolicy.ExpectedDigest
	if subtle.ConstantTimeCompare([]byte(expected), []byte(claims.PCRDigest)) != 1 {
		return fmt.Errorf("%w: secureboot PCR policy mismatch", ErrAttestationPolicy)
	}
	if !sameSelection(policy.PCRPolicy.Selection, claims.PCRSelection) {
		return fmt.Errorf("%w: secureboot PCR selection mismatch", ErrAttestationPolicy)
	}
	return nil
}
