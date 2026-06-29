// Package kmsplugin contains the OpenBao go-kms-wrapping plugin implementation.
package kmsplugin

import (
	"context"
	"errors"
	"fmt"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// ErrNotInitialized indicates the wrapper has not completed Init.
var ErrNotInitialized = errors.New("attested unseal wrapper is not initialized")

// ErrBackendUnavailable indicates the selected backend is not implemented yet.
var ErrBackendUnavailable = errors.New("attested unseal backend is unavailable")

// EncryptRequest carries one OpenBao plaintext wrapping operation.
type EncryptRequest struct {
	Plaintext []byte
	AAD       []byte
	KeyID     string
}

// EncryptResponse carries the wrapped OpenBao seal blob.
type EncryptResponse struct {
	Blob *wrapping.BlobInfo
}

// DecryptRequest carries one OpenBao ciphertext unwrapping operation.
type DecryptRequest struct {
	Blob  *wrapping.BlobInfo
	AAD   []byte
	KeyID string
}

// DecryptResponse carries the unwrapped OpenBao seal plaintext.
type DecryptResponse struct {
	Plaintext []byte
}

// BackendStatus describes backend readiness for diagnostics.
type BackendStatus struct {
	Ready bool
	KeyID string
	Mode  Mode
}

// Backend handles the actual wrapping operation after wrapper lifecycle setup.
type Backend interface {
	Encrypt(ctx context.Context, req EncryptRequest) (EncryptResponse, error)
	Decrypt(ctx context.Context, req DecryptRequest) (DecryptResponse, error)
	KeyID(ctx context.Context) (string, error)
	Status(ctx context.Context) (BackendStatus, error)
	Close(ctx context.Context) error
}

type backendFactory interface {
	NewBackend(ctx context.Context, config Config) (Backend, error)
}

type productionFactory struct{}

func (productionFactory) NewBackend(ctx context.Context, config Config) (Backend, error) {
	if config.Mode == ModeLocalTPM {
		return newLocalTPMBackend(ctx, config)
	}
	if config.Mode == ModeBroker {
		return newBrokerBackend(ctx, config)
	}
	return unavailableBackend{config: config}, nil
}

type unavailableBackend struct {
	config Config
}

func (b unavailableBackend) Encrypt(context.Context, EncryptRequest) (EncryptResponse, error) {
	return EncryptResponse{}, fmt.Errorf("%w: broker backend is not implemented", ErrBackendUnavailable)
}

func (b unavailableBackend) Decrypt(context.Context, DecryptRequest) (DecryptResponse, error) {
	return DecryptResponse{}, fmt.Errorf("%w: broker backend is not implemented", ErrBackendUnavailable)
}

func (b unavailableBackend) KeyID(context.Context) (string, error) {
	keyID := b.config.ConfiguredKeyID()
	if keyID == "" {
		return "", fmt.Errorf("%w: active broker key is unknown", ErrBackendUnavailable)
	}
	return keyID, nil
}

func (b unavailableBackend) Status(context.Context) (BackendStatus, error) {
	return BackendStatus{
		Ready: false,
		KeyID: b.config.ConfiguredKeyID(),
		Mode:  b.config.Mode,
	}, nil
}

func (b unavailableBackend) Close(context.Context) error {
	return nil
}
