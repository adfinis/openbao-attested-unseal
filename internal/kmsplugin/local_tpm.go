package kmsplugin

import (
	"context"
	"fmt"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

type localTPMBackend struct {
	config   Config
	ref      keyring.KeyRef
	ring     *keyring.Ring
	metadata tpmlocal.LocalKeyMetadata
}

func newLocalTPMBackend(ctx context.Context, config Config) (Backend, error) {
	ref := keyring.KeyRef{
		ClusterID: config.ClusterID,
		KeyID:     config.KeyID,
		Version:   config.KeyVersion,
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	ring, metadata, err := tpmlocal.LoadLocalRing(ctx, config.StatePath, tpmlocal.Device{Path: config.TPMDevice}, ref)
	if err != nil {
		return nil, fmt.Errorf("load local TPM keyring: %w", err)
	}
	return &localTPMBackend{
		config:   config,
		ref:      ref,
		ring:     ring,
		metadata: metadata,
	}, nil
}

func (b *localTPMBackend) Encrypt(ctx context.Context, req EncryptRequest) (EncryptResponse, error) {
	if err := b.validateRequestKey(req.KeyID); err != nil {
		return EncryptResponse{}, err
	}
	blob, err := b.ring.Encrypt(ctx, req.Plaintext, req.AAD)
	if err != nil {
		return EncryptResponse{}, err
	}
	return EncryptResponse{Blob: blob}, nil
}

func (b *localTPMBackend) Decrypt(ctx context.Context, req DecryptRequest) (DecryptResponse, error) {
	if err := b.validateRequestKey(req.KeyID); err != nil {
		return DecryptResponse{}, err
	}
	plaintext, err := b.ring.Decrypt(ctx, req.Blob, req.AAD)
	if err != nil {
		return DecryptResponse{}, err
	}
	return DecryptResponse{Plaintext: plaintext}, nil
}

func (b *localTPMBackend) KeyID(context.Context) (string, error) {
	return b.ref.String(), nil
}

func (b *localTPMBackend) Status(context.Context) (BackendStatus, error) {
	return BackendStatus{
		Ready: true,
		KeyID: b.ref.String(),
		Mode:  b.config.Mode,
	}, nil
}

func (b *localTPMBackend) Close(context.Context) error {
	return nil
}

func (b *localTPMBackend) validateRequestKey(keyID string) error {
	if keyID == "" || keyID == b.ref.String() {
		return nil
	}
	return fmt.Errorf(
		"%w: requested key %q does not match configured key %q",
		keyring.ErrKeyNotFound,
		keyID,
		b.ref.String(),
	)
}
