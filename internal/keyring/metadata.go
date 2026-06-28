package keyring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const (
	schemaVersion = 1
	// MaxAuthenticatedDataSize bounds parsed AAD metadata accepted by tests and future state loaders.
	MaxAuthenticatedDataSize = 4096
)

// Metadata is the authenticated metadata bound into every local ciphertext.
type Metadata struct {
	SchemaVersion uint32 `json:"schema_version"`
	Purpose       string `json:"purpose"`
	ClusterID     string `json:"cluster_id"`
	KeyID         string `json:"key_id"`
	KeyVersion    uint32 `json:"key_version"`
	Algorithm     string `json:"algorithm"`
	PolicyID      string `json:"policy_id"`
	BlobFormat    string `json:"blob_format"`
}

// KeyMetadata is the design-facing alias for Metadata.
type KeyMetadata = Metadata

type authenticatedData struct {
	Metadata  Metadata `json:"metadata"`
	CallerAAD []byte   `json:"caller_aad,omitempty"`
}

// NewMetadata builds authenticated metadata for a key version.
func NewMetadata(version KeyVersion) Metadata {
	return Metadata{
		SchemaVersion: schemaVersion,
		Purpose:       Purpose,
		ClusterID:     version.Ref.ClusterID,
		KeyID:         version.Ref.KeyID,
		KeyVersion:    version.Ref.Version,
		Algorithm:     string(version.Algorithm),
		PolicyID:      version.PolicyID,
		BlobFormat:    BlobFormat,
	}
}

// Validate checks that the metadata matches the expected local ciphertext shape.
func (m Metadata) Validate() error {
	if m.SchemaVersion != schemaVersion {
		return fmt.Errorf("%w: unsupported metadata schema version", ErrInvalidMetadata)
	}
	ref := KeyRef{
		ClusterID: m.ClusterID,
		KeyID:     m.KeyID,
		Version:   m.KeyVersion,
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	if Algorithm(m.Algorithm) != AlgorithmAES256GCM {
		return fmt.Errorf("%w: unsupported metadata algorithm", ErrInvalidMetadata)
	}
	if !validIdentifier(m.PolicyID) {
		return fmt.Errorf("%w: invalid metadata policy ID", ErrInvalidMetadata)
	}
	if m.Purpose != Purpose {
		return fmt.Errorf("%w: invalid metadata purpose", ErrInvalidMetadata)
	}
	if m.BlobFormat != BlobFormat {
		return fmt.Errorf("%w: invalid blob format", ErrInvalidMetadata)
	}
	return nil
}

// CanonicalAAD renders metadata and caller AAD in a stable JSON structure.
func (m Metadata) CanonicalAAD(callerAAD []byte) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(authenticatedData{
		Metadata:  m,
		CallerAAD: callerAAD,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal authenticated data: %w", err)
	}
	return encoded, nil
}

// ParseCanonicalAAD validates a canonical AAD payload produced by CanonicalAAD.
func ParseCanonicalAAD(encoded []byte) (Metadata, []byte, error) {
	if len(encoded) == 0 {
		return Metadata{}, nil, fmt.Errorf("%w: empty authenticated data", ErrInvalidMetadata)
	}
	if len(encoded) > MaxAuthenticatedDataSize {
		return Metadata{}, nil, fmt.Errorf("%w: authenticated data exceeds maximum size", ErrInvalidMetadata)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	var aad authenticatedData
	if err := decoder.Decode(&aad); err != nil {
		return Metadata{}, nil, fmt.Errorf("%w: parse authenticated data: %w", ErrInvalidMetadata, err)
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Metadata{}, nil, fmt.Errorf("%w: trailing authenticated data", ErrInvalidMetadata)
	}
	if err := aad.Metadata.Validate(); err != nil {
		return Metadata{}, nil, err
	}
	return aad.Metadata, cloneBytes(aad.CallerAAD), nil
}
