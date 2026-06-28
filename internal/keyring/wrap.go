package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// Encrypt wraps plaintext with the active key version.
func (r *Ring) Encrypt(ctx context.Context, plaintext []byte, callerAAD []byte) (*wrapping.BlobInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	version, err := r.Active(ctx)
	if err != nil {
		return nil, err
	}
	aad, err := NewMetadata(version).CanonicalAAD(callerAAD)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(version.Material)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		Iv:         nonce,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism: BlobMechanismAES256GCM,
			KeyId:     version.Ref.String(),
		},
	}, nil
}

// Decrypt unwraps a BlobInfo with the referenced usable key version.
func (r *Ring) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, callerAAD []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ref, err := validateBlob(blob)
	if err != nil {
		return nil, err
	}
	version, err := r.keyForDecrypt(ref)
	if err != nil {
		return nil, err
	}
	aad, err := NewMetadata(version).CanonicalAAD(callerAAD)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(version.Material)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, blob.GetIv(), blob.GetCiphertext(), aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt blob: %w", err)
	}
	return plaintext, nil
}

func validateBlob(blob *wrapping.BlobInfo) (KeyRef, error) {
	if blob == nil {
		return KeyRef{}, fmt.Errorf("%w: nil blob", ErrInvalidMetadata)
	}
	if len(blob.GetCiphertext()) == 0 {
		return KeyRef{}, fmt.Errorf("%w: empty ciphertext", ErrInvalidMetadata)
	}
	if len(blob.GetIv()) != NonceSize {
		return KeyRef{}, fmt.Errorf("%w: invalid nonce size", ErrInvalidMetadata)
	}
	keyInfo := blob.GetKeyInfo()
	if keyInfo == nil {
		return KeyRef{}, fmt.Errorf("%w: missing key info", ErrInvalidMetadata)
	}
	if keyInfo.GetMechanism() != BlobMechanismAES256GCM {
		return KeyRef{}, fmt.Errorf("%w: unsupported mechanism", ErrInvalidMetadata)
	}
	ref, err := ParseKeyRef(keyInfo.GetKeyId())
	if err != nil {
		return KeyRef{}, err
	}
	return ref, nil
}

func newAEAD(material []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	return aead, nil
}
