package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

const (
	// EvidenceSchemaVersion is the JSON TPM evidence schema version.
	EvidenceSchemaVersion uint32 = 1
	// EvidenceFormat identifies the serialized TPM quote payload.
	EvidenceFormat = "openbao-attested-unseal.tpm2-quote.v1"
)

var (
	ErrInvalidEvidence    = errors.New("invalid TPM evidence")
	ErrQuoteVerification  = errors.New("TPM quote verification failed")
	ErrAttestationPolicy  = errors.New("TPM attestation policy failed")
	ErrUnsupportedProfile = errors.New("unsupported TPM profile")
)

// Evidence contains the TPM quote payload stored in the generic protobuf envelope.
type Evidence struct {
	SchemaVersion  uint32            `json:"schema_version"`
	ChallengeID    string            `json:"challenge_id"`
	NonceHash      string            `json:"nonce_hash"`
	AKPublic       []byte            `json:"ak_public"`
	Quote          []byte            `json:"quote"`
	Signature      []byte            `json:"signature"`
	PCRSelection   PCRSelection      `json:"pcr_selection"`
	PCRValues      map[string]string `json:"pcr_values"`
	EKPublicHash   string            `json:"ek_public_hash,omitempty"`
	PlatformHint   string            `json:"platform_hint,omitempty"`
	CollectedBy    string            `json:"collected_by,omitempty"`
	CollectedAtUTC string            `json:"collected_at_utc,omitempty"`
}

// QuoteClaims are facts verified from a TPM quote.
type QuoteClaims struct {
	AKPublicHash string
	PCRSelection PCRSelection
	PCRDigest    string
	NonceHash    string
}

// CollectQuote reads PCR values and asks the TPM AK to quote the broker nonce.
func CollectQuote(
	rw io.ReadWriter,
	ak AK,
	challengeID string,
	nonce []byte,
	selection PCRSelection,
	platformHint string,
) (Evidence, error) {
	if rw == nil {
		return Evidence{}, fmt.Errorf("%w: TPM connection is required", ErrInvalidEvidence)
	}
	if ak.Handle == 0 || len(ak.Public) == 0 {
		return Evidence{}, fmt.Errorf("%w: AK is required", ErrInvalidEvidence)
	}
	if len(nonce) == 0 {
		return Evidence{}, fmt.Errorf("%w: nonce is required", ErrInvalidEvidence)
	}
	normalized, err := selection.Normalize()
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	legacySelection, err := normalized.legacy()
	if err != nil {
		return Evidence{}, err
	}
	quote, signature, err := legacytpm2.QuoteRaw(
		rw,
		ak.Handle,
		ak.auth,
		"",
		nonce,
		legacySelection,
		legacytpm2.AlgNull,
	)
	if err != nil {
		return Evidence{}, fmt.Errorf("collect TPM quote: %w", err)
	}
	pcrValues, err := legacytpm2.ReadPCRs(rw, legacySelection)
	if err != nil {
		return Evidence{}, fmt.Errorf("read PCR values: %w", err)
	}
	evidence := Evidence{
		SchemaVersion:  EvidenceSchemaVersion,
		ChallengeID:    challengeID,
		NonceHash:      NonceDigest(nonce),
		AKPublic:       ak.Public,
		Quote:          quote,
		Signature:      signature,
		PCRSelection:   normalized,
		PCRValues:      EncodePCRValues(pcrValues),
		PlatformHint:   platformHint,
		CollectedBy:    "go-tpm",
		CollectedAtUTC: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

// NonceDigest returns the stable challenge nonce digest representation.
func NonceDigest(nonce []byte) string {
	sum := sha256.Sum256(nonce)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PublicDigest returns the stable public TPM object digest representation.
func PublicDigest(public []byte) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Marshal serializes evidence as canonical JSON.
func (e Evidence) Marshal() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// UnmarshalEvidence parses TPM evidence JSON.
func UnmarshalEvidence(payload []byte) (Evidence, error) {
	var evidence Evidence
	if err := json.Unmarshal(payload, &evidence); err != nil {
		return Evidence{}, fmt.Errorf("%w: decode JSON: %v", ErrInvalidEvidence, err)
	}
	if err := evidence.Validate(); err != nil {
		return Evidence{}, err
	}
	return evidence, nil
}

// Validate checks evidence shape without trusting the quote.
func (e Evidence) Validate() error {
	if e.SchemaVersion != EvidenceSchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidEvidence)
	}
	if strings.TrimSpace(e.ChallengeID) == "" {
		return fmt.Errorf("%w: challenge ID is required", ErrInvalidEvidence)
	}
	if _, digest, err := parseDigestString(e.NonceHash); err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("%w: nonce hash must be sha256:hex", ErrInvalidEvidence)
	}
	if len(e.AKPublic) == 0 {
		return fmt.Errorf("%w: AK public area is required", ErrInvalidEvidence)
	}
	if len(e.Quote) == 0 {
		return fmt.Errorf("%w: quote is required", ErrInvalidEvidence)
	}
	if len(e.Signature) == 0 {
		return fmt.Errorf("%w: quote signature is required", ErrInvalidEvidence)
	}
	if _, err := e.PCRSelection.Normalize(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	values, err := DecodePCRValues(e.PCRValues)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	for _, pcr := range e.PCRSelection.PCRs {
		if _, ok := values[pcr]; !ok {
			return fmt.Errorf("%w: PCR %d value is required", ErrInvalidEvidence, pcr)
		}
	}
	return nil
}

// VerifyQuote verifies nonce binding, AK signature, quote type, PCR selection, and PCR digest.
func VerifyQuote(evidence Evidence, expectedNonce []byte) (QuoteClaims, error) {
	if err := evidence.Validate(); err != nil {
		return QuoteClaims{}, err
	}
	if err := verifyNonceHash(evidence, expectedNonce); err != nil {
		return QuoteClaims{}, err
	}
	akPublicHash, err := verifyAKSignature(evidence)
	if err != nil {
		return QuoteClaims{}, err
	}
	attestation, err := verifyAttestation(evidence, expectedNonce)
	if err != nil {
		return QuoteClaims{}, err
	}
	evidenceSelection, computedPCRDigest, err := verifyAttestedPCRs(evidence, attestation)
	if err != nil {
		return QuoteClaims{}, err
	}

	return QuoteClaims{
		AKPublicHash: akPublicHash,
		PCRSelection: evidenceSelection,
		PCRDigest:    digestString(evidenceSelection.Hash, computedPCRDigest),
		NonceHash:    evidence.NonceHash,
	}, nil
}

func verifyNonceHash(evidence Evidence, expectedNonce []byte) error {
	if len(expectedNonce) == 0 {
		return fmt.Errorf("%w: expected nonce is required", ErrQuoteVerification)
	}
	if got, want := evidence.NonceHash, NonceDigest(expectedNonce); got != want {
		return fmt.Errorf("%w: nonce hash mismatch", ErrQuoteVerification)
	}
	return nil
}

func verifyAKSignature(evidence Evidence) (string, error) {
	public, err := legacytpm2.DecodePublic(evidence.AKPublic)
	if err != nil {
		return "", fmt.Errorf("%w: decode AK public: %v", ErrQuoteVerification, err)
	}
	publicKey, err := public.Key()
	if err != nil {
		return "", fmt.Errorf("%w: decode AK public key: %v", ErrQuoteVerification, err)
	}
	signature, err := legacytpm2.DecodeSignature(bytes.NewBuffer(evidence.Signature))
	if err != nil {
		return "", fmt.Errorf("%w: decode signature: %v", ErrQuoteVerification, err)
	}
	if err := verifySignature(publicKey, signature, evidence.Quote); err != nil {
		return "", err
	}
	return PublicDigest(evidence.AKPublic), nil
}

func verifyAttestation(
	evidence Evidence,
	expectedNonce []byte,
) (*legacytpm2.AttestationData, error) {
	attestation, err := legacytpm2.DecodeAttestationData(evidence.Quote)
	if err != nil {
		return nil, fmt.Errorf("%w: decode attestation: %v", ErrQuoteVerification, err)
	}
	if attestation.Type != legacytpm2.TagAttestQuote || attestation.AttestedQuoteInfo == nil {
		return nil, fmt.Errorf("%w: attestation is not a quote", ErrQuoteVerification)
	}
	if !bytes.Equal(attestation.ExtraData, expectedNonce) {
		return nil, fmt.Errorf("%w: quote nonce mismatch", ErrQuoteVerification)
	}
	return attestation, nil
}

func verifyAttestedPCRs(
	evidence Evidence,
	attestation *legacytpm2.AttestationData,
) (PCRSelection, []byte, error) {
	quoteSelection, err := selectionFromLegacy(attestation.AttestedQuoteInfo.PCRSelection).Normalize()
	if err != nil {
		return PCRSelection{}, nil, fmt.Errorf("%w: quote PCR selection: %v", ErrQuoteVerification, err)
	}
	evidenceSelection, err := evidence.PCRSelection.Normalize()
	if err != nil {
		return PCRSelection{}, nil, err
	}
	if !sameSelection(quoteSelection, evidenceSelection) {
		return PCRSelection{}, nil, fmt.Errorf("%w: quote PCR selection mismatch", ErrQuoteVerification)
	}
	pcrValues, err := DecodePCRValues(evidence.PCRValues)
	if err != nil {
		return PCRSelection{}, nil, fmt.Errorf("%w: %v", ErrQuoteVerification, err)
	}
	computedPCRDigest, err := ComputePCRDigest(evidenceSelection, pcrValues)
	if err != nil {
		return PCRSelection{}, nil, fmt.Errorf("%w: compute PCR digest: %v", ErrQuoteVerification, err)
	}
	if !bytes.Equal(attestation.AttestedQuoteInfo.PCRDigest, computedPCRDigest) {
		return PCRSelection{}, nil, fmt.Errorf("%w: PCR digest mismatch", ErrQuoteVerification)
	}
	return evidenceSelection, computedPCRDigest, nil
}

func verifySignature(publicKey crypto.PublicKey, signature *legacytpm2.Signature, message []byte) error {
	switch signature.Alg {
	case legacytpm2.AlgRSASSA:
		return verifyRSASignature(publicKey, signature.RSA, message, false)
	case legacytpm2.AlgRSAPSS:
		return verifyRSASignature(publicKey, signature.RSA, message, true)
	case legacytpm2.AlgECDSA:
		return verifyECDSASignature(publicKey, signature.ECC, message)
	default:
		return fmt.Errorf("%w: unsupported signature algorithm 0x%x", ErrQuoteVerification, signature.Alg)
	}
}

func verifyRSASignature(
	publicKey crypto.PublicKey,
	signature *legacytpm2.SignatureRSA,
	message []byte,
	pss bool,
) error {
	if signature == nil {
		return fmt.Errorf("%w: missing RSA signature", ErrQuoteVerification)
	}
	hash, digest, err := hashMessage(signature.HashAlg, message)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQuoteVerification, err)
	}
	rsaPublic, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: AK is not an RSA key", ErrQuoteVerification)
	}
	if pss {
		if err := rsa.VerifyPSS(rsaPublic, hash, digest, signature.Signature, nil); err != nil {
			return fmt.Errorf("%w: RSA-PSS signature mismatch", ErrQuoteVerification)
		}
		return nil
	}
	if err := rsa.VerifyPKCS1v15(rsaPublic, hash, digest, signature.Signature); err != nil {
		return fmt.Errorf("%w: RSA signature mismatch", ErrQuoteVerification)
	}
	return nil
}

func verifyECDSASignature(publicKey crypto.PublicKey, signature *legacytpm2.SignatureECC, message []byte) error {
	if signature == nil {
		return fmt.Errorf("%w: missing ECDSA signature", ErrQuoteVerification)
	}
	_, digest, err := hashMessage(signature.HashAlg, message)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQuoteVerification, err)
	}
	ecdsaPublic, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: AK is not an ECDSA key", ErrQuoteVerification)
	}
	if !ecdsa.Verify(ecdsaPublic, digest, signature.R, signature.S) {
		return fmt.Errorf("%w: ECDSA signature mismatch", ErrQuoteVerification)
	}
	return nil
}

func hashMessage(alg legacytpm2.Algorithm, message []byte) (crypto.Hash, []byte, error) {
	hash, err := alg.Hash()
	if err != nil {
		return crypto.Hash(0), nil, err
	}
	h := hash.New()
	if _, err := h.Write(message); err != nil {
		return crypto.Hash(0), nil, err
	}
	return hash, h.Sum(nil), nil
}

func sameSelection(left PCRSelection, right PCRSelection) bool {
	if left.Hash != right.Hash || len(left.PCRs) != len(right.PCRs) {
		return false
	}
	for i := range left.PCRs {
		if left.PCRs[i] != right.PCRs[i] {
			return false
		}
	}
	return true
}
