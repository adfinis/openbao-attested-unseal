package kmsplugin

import (
	"context"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

// InMemoryBackend is a unit-test backend backed by the local keyring primitive.
type InMemoryBackend struct {
	Ring   *keyring.Ring
	Mode   Mode
	Closed bool
}

func (b *InMemoryBackend) Encrypt(ctx context.Context, req EncryptRequest) (EncryptResponse, error) {
	blob, err := b.Ring.Encrypt(ctx, req.Plaintext, req.AAD)
	if err != nil {
		return EncryptResponse{}, err
	}
	return EncryptResponse{Blob: blob}, nil
}

func (b *InMemoryBackend) Decrypt(ctx context.Context, req DecryptRequest) (DecryptResponse, error) {
	plaintext, err := b.Ring.Decrypt(ctx, req.Blob, req.AAD)
	if err != nil {
		return DecryptResponse{}, err
	}
	return DecryptResponse{Plaintext: plaintext}, nil
}

func (b *InMemoryBackend) KeyID(ctx context.Context) (string, error) {
	active, err := b.Ring.Active(ctx)
	if err != nil {
		return "", err
	}
	return active.Ref.String(), nil
}

func (b *InMemoryBackend) Status(ctx context.Context) (BackendStatus, error) {
	keyID, err := b.KeyID(ctx)
	if err != nil {
		return BackendStatus{}, err
	}
	return BackendStatus{Ready: !b.Closed, KeyID: keyID, Mode: b.Mode}, nil
}

func (b *InMemoryBackend) Close(context.Context) error {
	b.Closed = true
	return nil
}

type inMemoryFactory struct {
	backend *InMemoryBackend
}

func (f inMemoryFactory) NewBackend(context.Context, Config) (Backend, error) {
	return f.backend, nil
}
