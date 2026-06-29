package kmsplugin

import (
	"context"
	"fmt"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

type localTPMBackend struct {
	config   Config
	active   keyring.KeyRef
	ring     *keyring.Ring
	metadata []tpmlocal.LocalKeyMetadata
}

func newLocalTPMBackend(ctx context.Context, config Config) (Backend, error) {
	ring, metadata, err := tpmlocal.LoadLocalKeyring(
		ctx,
		config.StatePath,
		tpmlocal.Device{Path: config.TPMDevice},
		config.ClusterID,
		config.KeyID,
	)
	if err != nil {
		return nil, fmt.Errorf("load local TPM keyring: %w", err)
	}
	active, err := ring.Active(ctx)
	if err != nil {
		return nil, err
	}
	if config.KeyVersion != 0 && !metadataContainsVersion(metadata, config.KeyVersion) {
		return nil, fmt.Errorf("%w: configured local TPM key version was not found", keyring.ErrKeyNotFound)
	}
	return &localTPMBackend{
		config:   config,
		active:   active.Ref,
		ring:     ring,
		metadata: metadata,
	}, nil
}

func (b *localTPMBackend) Encrypt(ctx context.Context, req EncryptRequest) (EncryptResponse, error) {
	if err := b.validateEncryptRequestKey(req.KeyID); err != nil {
		return EncryptResponse{}, err
	}
	blob, err := b.ring.Encrypt(ctx, req.Plaintext, req.AAD)
	if err != nil {
		return EncryptResponse{}, err
	}
	return EncryptResponse{Blob: blob}, nil
}

func (b *localTPMBackend) Decrypt(ctx context.Context, req DecryptRequest) (DecryptResponse, error) {
	if err := b.validateDecryptRequestKey(req.KeyID, req.Blob); err != nil {
		return DecryptResponse{}, err
	}
	plaintext, err := b.ring.Decrypt(ctx, req.Blob, req.AAD)
	if err != nil {
		return DecryptResponse{}, err
	}
	return DecryptResponse{Plaintext: plaintext}, nil
}

func (b *localTPMBackend) KeyID(context.Context) (string, error) {
	return b.active.String(), nil
}

func (b *localTPMBackend) Status(context.Context) (BackendStatus, error) {
	return BackendStatus{
		Ready: true,
		KeyID: b.active.String(),
		Mode:  b.config.Mode,
	}, nil
}

func (b *localTPMBackend) Close(context.Context) error {
	return nil
}

func (b *localTPMBackend) validateEncryptRequestKey(keyID string) error {
	if keyID == "" || keyID == b.active.String() {
		return nil
	}
	return fmt.Errorf(
		"%w: requested key %q does not match active key %q",
		keyring.ErrKeyNotUsable,
		keyID,
		b.active.String(),
	)
}

func (b *localTPMBackend) validateDecryptRequestKey(keyID string, blob *wrapping.BlobInfo) error {
	if keyID == "" {
		return nil
	}
	if blob == nil || blob.GetKeyInfo() == nil {
		return fmt.Errorf("%w: missing blob key info", keyring.ErrInvalidMetadata)
	}
	blobKeyID := blob.GetKeyInfo().GetKeyId()
	if keyID == blobKeyID {
		return nil
	}
	return fmt.Errorf(
		"%w: requested key %q does not match blob key %q",
		keyring.ErrInvalidMetadata,
		keyID,
		blobKeyID,
	)
}

func metadataContainsVersion(metadata []tpmlocal.LocalKeyMetadata, version uint32) bool {
	for _, record := range metadata {
		if record.Version == version {
			return true
		}
	}
	return false
}
