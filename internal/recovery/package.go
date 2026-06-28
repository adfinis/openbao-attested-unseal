// Package recovery implements offline recovery package metadata and shares.
package recovery

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

const (
	// SchemaVersion is the recovery package and share schema version.
	SchemaVersion = 1
	// DefaultThreshold is the recommended recovery threshold.
	DefaultThreshold = 3
	// DefaultShares is the recommended recovery share count.
	DefaultShares = 5
	// SharePrefix identifies human-transferable recovery shares.
	SharePrefix = "raus1."
)

var (
	// ErrInvalidPackage indicates malformed recovery metadata.
	ErrInvalidPackage = errors.New("invalid recovery package")
	// ErrInvalidShare indicates a malformed or mismatched recovery share.
	ErrInvalidShare = errors.New("invalid recovery share")
	// ErrThreshold indicates insufficient valid recovery shares.
	ErrThreshold = errors.New("recovery threshold not met")
)

// Package contains non-secret recovery metadata and one-time printable shares.
type Package struct {
	Metadata PackageMetadata `json:"metadata"`
	Shares   []string        `json:"shares"`
}

// PackageMetadata is safe to persist with broker state and backups.
type PackageMetadata struct {
	SchemaVersion     uint32   `json:"schema_version"`
	PackageID         string   `json:"recovery_package_id"`
	ClusterID         string   `json:"cluster_id"`
	KeyID             string   `json:"key_id"`
	CreatedAt         string   `json:"created_at"`
	Threshold         int      `json:"threshold"`
	Shares            int      `json:"shares"`
	KDF               string   `json:"kdf"`
	WrappingAlgorithm string   `json:"wrapping_algorithm"`
	SecretChecksum    string   `json:"secret_checksum"`
	AllowedOperations []string `json:"allowed_operations"`
}

// Create builds recovery metadata and Shamir shares for secret.
func Create(
	packageID string,
	clusterID string,
	keyID string,
	secret []byte,
	threshold int,
	shares int,
	now time.Time,
) (Package, error) {
	if err := validateCreateInputs(packageID, clusterID, keyID, secret, threshold, shares); err != nil {
		return Package{}, err
	}
	points, err := splitSecret(secret, threshold, shares, rand.Reader)
	if err != nil {
		return Package{}, err
	}
	metadata := PackageMetadata{
		SchemaVersion:     SchemaVersion,
		PackageID:         packageID,
		ClusterID:         clusterID,
		KeyID:             keyID,
		CreatedAt:         now.UTC().Format(time.RFC3339Nano),
		Threshold:         threshold,
		Shares:            shares,
		KDF:               "none",
		WrappingAlgorithm: string(keyring.AlgorithmAES256GCM),
		SecretChecksum:    checksum(secret),
		AllowedOperations: []string{"recover-enroll"},
	}
	encoded := make([]string, 0, len(points))
	for _, point := range points {
		encoded = append(encoded, encodeShare(shareEnvelope{
			SchemaVersion: SchemaVersion,
			PackageID:     packageID,
			Index:         int(point.index),
			Value:         base64.StdEncoding.EncodeToString(point.value),
		}))
	}
	return Package{Metadata: metadata, Shares: encoded}, nil
}

// Recover reconstructs the protected secret from a threshold of shares.
func Recover(metadata PackageMetadata, encodedShares []string) ([]byte, error) {
	if err := metadata.Validate(); err != nil {
		return nil, err
	}
	if len(encodedShares) < metadata.Threshold {
		return nil, ErrThreshold
	}
	points := make([]sharePoint, 0, len(encodedShares))
	seen := make(map[byte]struct{})
	for _, encoded := range encodedShares {
		share, err := parseShare(encoded)
		if err != nil {
			return nil, err
		}
		if share.PackageID != metadata.PackageID {
			return nil, fmt.Errorf("%w: package ID mismatch", ErrInvalidShare)
		}
		if share.Index <= 0 || share.Index > metadata.Shares {
			return nil, fmt.Errorf("%w: share index out of range", ErrInvalidShare)
		}
		// #nosec G115 -- metadata validation bounds share indexes to uint8 range.
		index := byte(share.Index)
		if _, ok := seen[index]; ok {
			return nil, fmt.Errorf("%w: duplicate share", ErrInvalidShare)
		}
		seen[index] = struct{}{}
		value, err := base64.StdEncoding.DecodeString(share.Value)
		if err != nil {
			return nil, fmt.Errorf("%w: decode share value: %w", ErrInvalidShare, err)
		}
		points = append(points, sharePoint{index: index, value: value})
	}
	if len(points) < metadata.Threshold {
		return nil, ErrThreshold
	}
	points = points[:metadata.Threshold]
	secret, err := combineShares(points)
	if err != nil {
		return nil, err
	}
	if checksum(secret) != metadata.SecretChecksum {
		return nil, fmt.Errorf("%w: checksum mismatch", ErrInvalidShare)
	}
	return secret, nil
}

// Validate checks persisted recovery metadata.
func (m PackageMetadata) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidPackage)
	}
	if err := keyring.ValidateIdentifier(m.PackageID); err != nil {
		return fmt.Errorf("%w: invalid recovery package ID", ErrInvalidPackage)
	}
	if err := keyring.ValidateIdentifier(m.ClusterID); err != nil {
		return fmt.Errorf("%w: invalid cluster ID", ErrInvalidPackage)
	}
	if err := keyring.ValidateIdentifier(m.KeyID); err != nil {
		return fmt.Errorf("%w: invalid key ID", ErrInvalidPackage)
	}
	if m.Threshold <= 0 || m.Shares <= 0 || m.Threshold > m.Shares || m.Shares > 255 {
		return fmt.Errorf("%w: invalid threshold", ErrInvalidPackage)
	}
	if m.KDF != "none" {
		return fmt.Errorf("%w: unsupported KDF", ErrInvalidPackage)
	}
	if m.WrappingAlgorithm != string(keyring.AlgorithmAES256GCM) {
		return fmt.Errorf("%w: unsupported wrapping algorithm", ErrInvalidPackage)
	}
	if !strings.HasPrefix(m.SecretChecksum, "sha256:") {
		return fmt.Errorf("%w: invalid checksum", ErrInvalidPackage)
	}
	if _, err := time.Parse(time.RFC3339Nano, m.CreatedAt); err != nil {
		return fmt.Errorf("%w: invalid created_at", ErrInvalidPackage)
	}
	if !slices.Contains(m.AllowedOperations, "recover-enroll") {
		return fmt.Errorf("%w: missing recover-enroll operation", ErrInvalidPackage)
	}
	return nil
}

type shareEnvelope struct {
	SchemaVersion uint32 `json:"schema_version"`
	PackageID     string `json:"recovery_package_id"`
	Index         int    `json:"index"`
	Value         string `json:"value"`
}

type sharePoint struct {
	index byte
	value []byte
}

func validateCreateInputs(
	packageID string,
	clusterID string,
	keyID string,
	secret []byte,
	threshold int,
	shares int,
) error {
	if err := keyring.ValidateIdentifier(packageID); err != nil {
		return fmt.Errorf("%w: invalid recovery package ID", ErrInvalidPackage)
	}
	if err := keyring.ValidateIdentifier(clusterID); err != nil {
		return fmt.Errorf("%w: invalid cluster ID", ErrInvalidPackage)
	}
	if err := keyring.ValidateIdentifier(keyID); err != nil {
		return fmt.Errorf("%w: invalid key ID", ErrInvalidPackage)
	}
	if len(secret) == 0 {
		return fmt.Errorf("%w: empty secret", ErrInvalidPackage)
	}
	if threshold <= 0 || shares <= 0 || threshold > shares || shares > 255 {
		return fmt.Errorf("%w: invalid threshold", ErrInvalidPackage)
	}
	return nil
}

func encodeShare(share shareEnvelope) string {
	encoded, err := json.Marshal(share)
	if err != nil {
		panic(err)
	}
	return SharePrefix + base64.RawURLEncoding.EncodeToString(encoded)
}

func parseShare(encoded string) (shareEnvelope, error) {
	if !strings.HasPrefix(encoded, SharePrefix) {
		return shareEnvelope{}, fmt.Errorf("%w: missing prefix", ErrInvalidShare)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encoded, SharePrefix))
	if err != nil {
		return shareEnvelope{}, fmt.Errorf("%w: decode share: %w", ErrInvalidShare, err)
	}
	var share shareEnvelope
	if err := json.Unmarshal(raw, &share); err != nil {
		return shareEnvelope{}, fmt.Errorf("%w: parse share: %w", ErrInvalidShare, err)
	}
	if share.SchemaVersion != SchemaVersion {
		return shareEnvelope{}, fmt.Errorf("%w: unsupported schema version", ErrInvalidShare)
	}
	return share, nil
}

func checksum(secret []byte) string {
	sum := sha256.Sum256(secret)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func splitSecret(secret []byte, threshold int, shares int, random io.Reader) ([]sharePoint, error) {
	points := make([]sharePoint, shares)
	for i := range points {
		points[i] = sharePoint{index: byte(i + 1), value: make([]byte, len(secret))}
	}
	for offset, b := range secret {
		coefficients := make([]byte, threshold)
		coefficients[0] = b
		if threshold > 1 {
			if _, err := io.ReadFull(random, coefficients[1:]); err != nil {
				return nil, fmt.Errorf("generate share coefficients: %w", err)
			}
		}
		for i := range points {
			points[i].value[offset] = evalPolynomial(coefficients, points[i].index)
		}
	}
	return points, nil
}

func combineShares(points []sharePoint) ([]byte, error) {
	if len(points) == 0 {
		return nil, ErrThreshold
	}
	secretLen := len(points[0].value)
	for _, point := range points {
		if point.index == 0 {
			return nil, fmt.Errorf("%w: zero index", ErrInvalidShare)
		}
		if len(point.value) != secretLen {
			return nil, fmt.Errorf("%w: share length mismatch", ErrInvalidShare)
		}
	}
	secret := make([]byte, secretLen)
	for offset := range secret {
		var value byte
		for i, point := range points {
			basis := byte(1)
			for j, other := range points {
				if i == j {
					continue
				}
				basis = gfMul(basis, gfDiv(other.index, point.index^other.index))
			}
			value ^= gfMul(point.value[offset], basis)
		}
		secret[offset] = value
	}
	return secret, nil
}

func evalPolynomial(coefficients []byte, x byte) byte {
	var result byte
	for i := len(coefficients) - 1; i >= 0; i-- {
		result = gfMul(result, x) ^ coefficients[i]
	}
	return result
}

func gfMul(a byte, b byte) byte {
	var product byte
	for b != 0 {
		if b&1 != 0 {
			product ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return product
}

func gfPow(a byte, power int) byte {
	result := byte(1)
	for power > 0 {
		if power&1 != 0 {
			result = gfMul(result, a)
		}
		a = gfMul(a, a)
		power >>= 1
	}
	return result
}

func gfDiv(a byte, b byte) byte {
	if b == 0 {
		panic("divide by zero in GF(256)")
	}
	return gfMul(a, gfPow(b, 254))
}
