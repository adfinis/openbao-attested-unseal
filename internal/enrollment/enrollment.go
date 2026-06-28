// Package enrollment implements brokered enrollment request and grant formats.
package enrollment

import (
	"bytes"
	"crypto/ed25519"
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

	"github.com/dc-tec/openbao-attested-unseal/internal/keyring"
)

const (
	// SchemaVersion is the enrollment request and grant schema version.
	SchemaVersion = 1
	// ModeBroker identifies brokered subject enrollment.
	ModeBroker = "broker"
)

var (
	// ErrInvalidRequest indicates a malformed enrollment request.
	ErrInvalidRequest = errors.New("invalid enrollment request")
	// ErrInvalidGrant indicates a malformed enrollment grant.
	ErrInvalidGrant = errors.New("invalid enrollment grant")
	// ErrExpired indicates an expired request or grant.
	ErrExpired = errors.New("enrollment artifact expired")
	// ErrSignature indicates a failed grant signature check.
	ErrSignature = errors.New("invalid enrollment grant signature")
)

// Request is written by a target that wants brokered enrollment.
type Request struct {
	SchemaVersion     uint32   `json:"schema_version"`
	RequestID         string   `json:"request_id"`
	ClusterID         string   `json:"cluster_id"`
	SubjectID         string   `json:"subject_id"`
	Mode              string   `json:"mode"`
	AllowedOperations []string `json:"allowed_operations"`
	EvidenceFormat    string   `json:"evidence_format"`
	EvidencePayload   string   `json:"evidence_payload,omitempty"`
	EvidenceHash      string   `json:"evidence_hash"`
	PublicIdentity    string   `json:"public_identity"`
	Nonce             string   `json:"nonce"`
	ExpiresAt         string   `json:"expires_at"`
}

// Grant is issued by an operator for a validated brokered request.
type Grant struct {
	SchemaVersion     uint32   `json:"schema_version"`
	GrantID           string   `json:"grant_id"`
	RequestID         string   `json:"request_id"`
	ClusterID         string   `json:"cluster_id"`
	KeyID             string   `json:"key_id"`
	SubjectID         string   `json:"subject_id"`
	Mode              string   `json:"mode"`
	ApprovalMode      string   `json:"approval_mode"`
	AllowedOperations []string `json:"allowed_operations"`
	PolicyID          string   `json:"policy_id"`
	EvidenceHash      string   `json:"evidence_hash"`
	ExpiresAt         string   `json:"expires_at"`
	OneTime           bool     `json:"one_time"`
	IssuerPublicKey   string   `json:"issuer_public_key"`
	Signature         string   `json:"signature"`
}

// RequestOptions describes a brokered enrollment request.
type RequestOptions struct {
	RequestID         string
	ClusterID         string
	SubjectID         string
	AllowedOperations []string
	EvidenceFormat    string
	EvidencePayload   []byte
	PublicIdentity    string
	Nonce             string
	ExpiresAt         time.Time
}

// GrantOptions describes an issued brokered enrollment grant.
type GrantOptions struct {
	GrantID      string
	KeyID        string
	PolicyID     string
	ApprovalMode string
	ExpiresAt    time.Time
	OneTime      bool
}

// NewRequest creates an enrollment request with canonical evidence hash.
func NewRequest(opts RequestOptions) (Request, error) {
	if len(opts.AllowedOperations) == 0 {
		opts.AllowedOperations = []string{"wrap", "unwrap"}
	}
	request := Request{
		SchemaVersion:     SchemaVersion,
		RequestID:         opts.RequestID,
		ClusterID:         opts.ClusterID,
		SubjectID:         opts.SubjectID,
		Mode:              ModeBroker,
		AllowedOperations: normalizeOperations(opts.AllowedOperations),
		EvidenceFormat:    opts.EvidenceFormat,
		EvidencePayload:   base64.StdEncoding.EncodeToString(opts.EvidencePayload),
		EvidenceHash:      evidenceHash(opts.EvidencePayload),
		PublicIdentity:    opts.PublicIdentity,
		Nonce:             opts.Nonce,
		ExpiresAt:         opts.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	if err := request.Validate(time.Now()); err != nil {
		return Request{}, err
	}
	return request, nil
}

// GenerateIssuer creates an Ed25519 issuer key pair.
func GenerateIssuer(random io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}
	publicKey, privateKey, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, nil, fmt.Errorf("generate enrollment issuer key: %w", err)
	}
	return publicKey, privateKey, nil
}

// IssueGrant validates request and returns a signed grant.
func IssueGrant(request Request, privateKey ed25519.PrivateKey, opts GrantOptions, now time.Time) (Grant, error) {
	if err := request.Validate(now); err != nil {
		return Grant{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return Grant{}, fmt.Errorf("%w: invalid issuer key", ErrInvalidGrant)
	}
	grant := Grant{
		SchemaVersion:     SchemaVersion,
		GrantID:           opts.GrantID,
		RequestID:         request.RequestID,
		ClusterID:         request.ClusterID,
		KeyID:             opts.KeyID,
		SubjectID:         request.SubjectID,
		Mode:              ModeBroker,
		ApprovalMode:      normalizeApprovalMode(opts.ApprovalMode),
		AllowedOperations: request.AllowedOperations,
		PolicyID:          opts.PolicyID,
		EvidenceHash:      request.EvidenceHash,
		ExpiresAt:         opts.ExpiresAt.UTC().Format(time.RFC3339Nano),
		OneTime:           opts.OneTime,
		IssuerPublicKey:   base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
	}
	if err := grant.validateUnsigned(now); err != nil {
		return Grant{}, err
	}
	payload, err := grant.signingPayload()
	if err != nil {
		return Grant{}, err
	}
	grant.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := grant.Verify(now); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

// Validate checks request structure and expiry.
func (r Request) Validate(now time.Time) error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidRequest)
	}
	if err := keyring.ValidateIdentifier(r.RequestID); err != nil {
		return fmt.Errorf("%w: invalid request ID", ErrInvalidRequest)
	}
	if err := keyring.ValidateIdentifier(r.ClusterID); err != nil {
		return fmt.Errorf("%w: invalid cluster ID", ErrInvalidRequest)
	}
	if err := keyring.ValidateIdentifier(r.SubjectID); err != nil {
		return fmt.Errorf("%w: invalid subject ID", ErrInvalidRequest)
	}
	if r.Mode != ModeBroker {
		return fmt.Errorf("%w: unsupported mode", ErrInvalidRequest)
	}
	if err := validateOperations(r.AllowedOperations); err != nil {
		return err
	}
	if strings.TrimSpace(r.EvidenceFormat) == "" {
		return fmt.Errorf("%w: evidence format is required", ErrInvalidRequest)
	}
	if !strings.HasPrefix(r.EvidenceHash, "sha256:") {
		return fmt.Errorf("%w: invalid evidence hash", ErrInvalidRequest)
	}
	if strings.TrimSpace(r.PublicIdentity) == "" {
		return fmt.Errorf("%w: public identity is required", ErrInvalidRequest)
	}
	if strings.TrimSpace(r.Nonce) == "" {
		return fmt.Errorf("%w: nonce is required", ErrInvalidRequest)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: invalid expiry", ErrInvalidRequest)
	}
	if !now.Before(expiresAt) {
		return ErrExpired
	}
	return nil
}

// Verify validates grant structure, expiry, and signature.
func (g Grant) Verify(now time.Time) error {
	if err := g.validateUnsigned(now); err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.DecodeString(g.IssuerPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid issuer public key", ErrInvalidGrant)
	}
	signature, err := base64.StdEncoding.DecodeString(g.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: invalid signature encoding", ErrInvalidGrant)
	}
	payload, err := g.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrSignature
	}
	return nil
}

func (g Grant) validateUnsigned(now time.Time) error {
	if g.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: unsupported schema version", ErrInvalidGrant)
	}
	for label, value := range map[string]string{
		"grant ID":   g.GrantID,
		"request ID": g.RequestID,
		"cluster ID": g.ClusterID,
		"key ID":     g.KeyID,
		"subject ID": g.SubjectID,
		"policy ID":  g.PolicyID,
	} {
		if err := keyring.ValidateIdentifier(value); err != nil {
			return fmt.Errorf("%w: invalid %s", ErrInvalidGrant, label)
		}
	}
	if g.Mode != ModeBroker {
		return fmt.Errorf("%w: unsupported mode", ErrInvalidGrant)
	}
	if g.ApprovalMode != "single-operator" && g.ApprovalMode != "quorum" {
		return fmt.Errorf("%w: unsupported approval mode", ErrInvalidGrant)
	}
	if err := validateOperations(g.AllowedOperations); err != nil {
		return err
	}
	if !strings.HasPrefix(g.EvidenceHash, "sha256:") {
		return fmt.Errorf("%w: invalid evidence hash", ErrInvalidGrant)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%w: invalid expiry", ErrInvalidGrant)
	}
	if !now.Before(expiresAt) {
		return ErrExpired
	}
	return nil
}

func (g Grant) signingPayload() ([]byte, error) {
	unsigned := struct {
		SchemaVersion     uint32   `json:"schema_version"`
		GrantID           string   `json:"grant_id"`
		RequestID         string   `json:"request_id"`
		ClusterID         string   `json:"cluster_id"`
		KeyID             string   `json:"key_id"`
		SubjectID         string   `json:"subject_id"`
		Mode              string   `json:"mode"`
		ApprovalMode      string   `json:"approval_mode"`
		AllowedOperations []string `json:"allowed_operations"`
		PolicyID          string   `json:"policy_id"`
		EvidenceHash      string   `json:"evidence_hash"`
		ExpiresAt         string   `json:"expires_at"`
		OneTime           bool     `json:"one_time"`
		IssuerPublicKey   string   `json:"issuer_public_key"`
	}{
		SchemaVersion:     g.SchemaVersion,
		GrantID:           g.GrantID,
		RequestID:         g.RequestID,
		ClusterID:         g.ClusterID,
		KeyID:             g.KeyID,
		SubjectID:         g.SubjectID,
		Mode:              g.Mode,
		ApprovalMode:      g.ApprovalMode,
		AllowedOperations: g.AllowedOperations,
		PolicyID:          g.PolicyID,
		EvidenceHash:      g.EvidenceHash,
		ExpiresAt:         g.ExpiresAt,
		OneTime:           g.OneTime,
		IssuerPublicKey:   g.IssuerPublicKey,
	}
	return json.Marshal(unsigned)
}

func normalizeApprovalMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "single-operator"
	}
	return mode
}

func evidenceHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeOperations(operations []string) []string {
	out := make([]string, 0, len(operations))
	seen := make(map[string]struct{})
	for _, operation := range operations {
		operation = strings.ToLower(strings.TrimSpace(operation))
		if operation == "" {
			continue
		}
		if _, ok := seen[operation]; ok {
			continue
		}
		seen[operation] = struct{}{}
		out = append(out, operation)
	}
	slices.Sort(out)
	return out
}

func validateOperations(operations []string) error {
	if len(operations) == 0 {
		return fmt.Errorf("%w: operations are required", ErrInvalidRequest)
	}
	for _, operation := range operations {
		switch operation {
		case "wrap", "unwrap":
		default:
			return fmt.Errorf("%w: unsupported operation %q", ErrInvalidRequest, operation)
		}
	}
	return nil
}

// SameGrant reports whether two grants have identical signed payloads.
func SameGrant(left Grant, right Grant) bool {
	leftPayload, leftErr := left.signingPayload()
	rightPayload, rightErr := right.signingPayload()
	return leftErr == nil && rightErr == nil && bytes.Equal(leftPayload, rightPayload)
}
