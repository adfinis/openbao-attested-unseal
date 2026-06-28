package tpm

import (
	"crypto/sha1" //nolint:gosec // TPM PCR SHA-1 banks must be parsed for legacy platform evidence.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"slices"
	"strconv"
	"strings"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

const (
	HashSHA1   = "sha1"
	HashSHA256 = "sha256"
	HashSHA384 = "sha384"
	HashSHA512 = "sha512"
)

// PCRSelection identifies one TPM PCR bank and the indexes quoted from it.
type PCRSelection struct {
	Hash string `json:"hash"`
	PCRs []int  `json:"pcrs"`
}

// PCRPolicy stores an enrolled PCR digest for a TPM-backed policy mode.
type PCRPolicy struct {
	Selection      PCRSelection      `json:"selection"`
	ExpectedDigest string            `json:"expected_digest"`
	CapturedValues map[string]string `json:"captured_values,omitempty"`
	Profile        string            `json:"profile,omitempty"`
}

// Normalize validates and returns a copy with sorted PCR indexes.
func (s PCRSelection) Normalize() (PCRSelection, error) {
	hashName := strings.ToLower(strings.TrimSpace(s.Hash))
	if hashName == "" {
		hashName = HashSHA256
	}
	if err := validateHashName(hashName); err != nil {
		return PCRSelection{}, err
	}
	if len(s.PCRs) == 0 {
		return PCRSelection{}, fmt.Errorf("PCR selection must include at least one PCR")
	}
	pcrs := slices.Clone(s.PCRs)
	slices.Sort(pcrs)
	for i, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return PCRSelection{}, fmt.Errorf("PCR index %d is out of range", pcr)
		}
		if i > 0 && pcr == pcrs[i-1] {
			return PCRSelection{}, fmt.Errorf("duplicate PCR index %d", pcr)
		}
	}
	return PCRSelection{Hash: hashName, PCRs: pcrs}, nil
}

func (s PCRSelection) contains(index int) bool {
	for _, pcr := range s.PCRs {
		if pcr == index {
			return true
		}
	}
	return false
}

func (s PCRSelection) legacy() (legacytpm2.PCRSelection, error) {
	normalized, err := s.Normalize()
	if err != nil {
		return legacytpm2.PCRSelection{}, err
	}
	alg, err := legacyHash(normalized.Hash)
	if err != nil {
		return legacytpm2.PCRSelection{}, err
	}
	return legacytpm2.PCRSelection{Hash: alg, PCRs: normalized.PCRs}, nil
}

func selectionFromLegacy(sel legacytpm2.PCRSelection) PCRSelection {
	return PCRSelection{
		Hash: hashName(sel.Hash),
		PCRs: slices.Clone(sel.PCRs),
	}
}

// NewPCRPolicy computes a policy digest from observed PCR values.
func NewPCRPolicy(selection PCRSelection, values map[int][]byte, profile string) (PCRPolicy, error) {
	digest, err := ComputePCRDigest(selection, values)
	if err != nil {
		return PCRPolicy{}, err
	}
	normalized, err := selection.Normalize()
	if err != nil {
		return PCRPolicy{}, err
	}
	return PCRPolicy{
		Selection:      normalized,
		ExpectedDigest: digestString(normalized.Hash, digest),
		CapturedValues: EncodePCRValues(values),
		Profile:        profile,
	}, nil
}

// ComputePCRDigest returns the TPM quote digest for selected PCR values.
func ComputePCRDigest(selection PCRSelection, values map[int][]byte) ([]byte, error) {
	normalized, err := selection.Normalize()
	if err != nil {
		return nil, err
	}
	h, err := newHash(normalized.Hash)
	if err != nil {
		return nil, err
	}
	size, err := hashDigestSize(normalized.Hash)
	if err != nil {
		return nil, err
	}
	for _, pcr := range normalized.PCRs {
		value, ok := values[pcr]
		if !ok {
			return nil, fmt.Errorf("PCR %d value is required", pcr)
		}
		if len(value) != size {
			return nil, fmt.Errorf("PCR %d digest size = %d, want %d", pcr, len(value), size)
		}
		if _, err := h.Write(value); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

// EncodePCRValues returns a stable JSON representation keyed by PCR index.
func EncodePCRValues(values map[int][]byte) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for index, value := range values {
		out[strconv.Itoa(index)] = hex.EncodeToString(value)
	}
	return out
}

// DecodePCRValues parses a JSON PCR value map keyed by PCR index.
func DecodePCRValues(values map[string]string) (map[int][]byte, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("PCR values are required")
	}
	out := make(map[int][]byte, len(values))
	for rawIndex, rawValue := range values {
		index, err := strconv.Atoi(rawIndex)
		if err != nil || index < 0 || index > 23 {
			return nil, fmt.Errorf("invalid PCR index %q", rawIndex)
		}
		value, err := hex.DecodeString(strings.TrimPrefix(rawValue, "0x"))
		if err != nil {
			return nil, fmt.Errorf("decode PCR %d value: %w", index, err)
		}
		out[index] = value
	}
	return out, nil
}

func digestString(hashName string, digest []byte) string {
	return strings.ToLower(hashName) + ":" + hex.EncodeToString(digest)
}

func parseDigestString(raw string) (string, []byte, error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("digest must use hash:hex format")
	}
	hashName := strings.ToLower(parts[0])
	if err := validateHashName(hashName); err != nil {
		return "", nil, err
	}
	digest, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decode digest: %w", err)
	}
	return hashName, digest, nil
}

func legacyHash(hashName string) (legacytpm2.Algorithm, error) {
	switch strings.ToLower(hashName) {
	case HashSHA1:
		return legacytpm2.AlgSHA1, nil
	case HashSHA256:
		return legacytpm2.AlgSHA256, nil
	case HashSHA384:
		return legacytpm2.AlgSHA384, nil
	case HashSHA512:
		return legacytpm2.AlgSHA512, nil
	default:
		return legacytpm2.AlgUnknown, fmt.Errorf("unsupported PCR hash %q", hashName)
	}
}

func hashName(alg legacytpm2.Algorithm) string {
	switch alg {
	case legacytpm2.AlgSHA1:
		return HashSHA1
	case legacytpm2.AlgSHA256:
		return HashSHA256
	case legacytpm2.AlgSHA384:
		return HashSHA384
	case legacytpm2.AlgSHA512:
		return HashSHA512
	default:
		return fmt.Sprintf("0x%x", uint16(alg))
	}
}

func validateHashName(hashName string) error {
	switch strings.ToLower(hashName) {
	case HashSHA1, HashSHA256, HashSHA384, HashSHA512:
		return nil
	default:
		return fmt.Errorf("unsupported hash %q", hashName)
	}
}

func newHash(hashName string) (hash.Hash, error) {
	switch strings.ToLower(hashName) {
	case HashSHA1:
		return sha1.New(), nil //nolint:gosec // TPM PCR SHA-1 bank validation, not signature or AEAD crypto.
	case HashSHA256:
		return sha256.New(), nil
	case HashSHA384:
		return sha512.New384(), nil
	case HashSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash %q", hashName)
	}
}

func hashDigestSize(hashName string) (int, error) {
	switch strings.ToLower(hashName) {
	case HashSHA1:
		return sha1.Size, nil
	case HashSHA256:
		return sha256.Size, nil
	case HashSHA384:
		return sha512.Size384, nil
	case HashSHA512:
		return sha512.Size, nil
	default:
		return 0, fmt.Errorf("unsupported hash %q", hashName)
	}
}
