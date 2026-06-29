package kmsplugin

import (
	"context"
	"fmt"
	"sync"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// WrapperType is the stable OpenBao go-kms-wrapping type for this plugin.
const WrapperType wrapping.WrapperType = "attested"

// Wrapper implements the OpenBao go-kms-wrapping interface.
type Wrapper struct {
	mu      sync.RWMutex
	config  Config
	factory backendFactory
	backend Backend
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

// NewWrapper constructs the production wrapper scaffold.
func NewWrapper() *Wrapper {
	return NewWrapperWithFactory(productionFactory{})
}

// NewWrapperWithFactory constructs a wrapper with an injected backend factory.
func NewWrapperWithFactory(factory backendFactory) *Wrapper {
	return &Wrapper{factory: factory}
}

// Type returns the stable wrapper type.
func (w *Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return WrapperType, nil
}

// SetConfig validates and stores wrapper configuration.
func (w *Wrapper) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	config, err := parseConfig(opts.GetWithConfigMap())
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.backend != nil {
		return nil, fmt.Errorf("wrapper is already initialized: %w", wrapping.ErrInvalidParameter)
	}
	backend, err := w.newBackendLocked(ctx, config)
	if err != nil {
		return nil, err
	}
	w.config = config
	w.backend = backend

	return &wrapping.WrapperConfig{
		Metadata: map[string]string{
			"broker_addr": config.BrokerAddress,
			"cluster_id":  config.ClusterID,
			"key_id":      config.ConfiguredKeyID(),
			"mode":        string(config.Mode),
			"state_path":  config.StatePath,
			"tpm_device":  config.TPMDevice,
			"type":        WrapperType.String(),
		},
	}, nil
}

// Init initializes the selected backend.
func (w *Wrapper) Init(ctx context.Context, _ ...wrapping.Option) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.config.Mode == "" {
		return fmt.Errorf("%w: SetConfig must be called before Init", ErrNotInitialized)
	}
	if w.backend != nil {
		return nil
	}
	backend, err := w.newBackendLocked(ctx, w.config)
	if err != nil {
		return err
	}
	w.backend = backend
	return nil
}

// Encrypt delegates plaintext wrapping to the initialized backend.
func (w *Wrapper) Encrypt(
	ctx context.Context,
	plaintext []byte,
	options ...wrapping.Option,
) (*wrapping.BlobInfo, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	backend, err := w.currentBackend()
	if err != nil {
		return nil, err
	}
	resp, err := backend.Encrypt(ctx, EncryptRequest{
		Plaintext: plaintext,
		AAD:       opts.GetWithAad(),
		KeyID:     opts.GetWithKeyId(),
	})
	if err != nil {
		return nil, err
	}
	traceWrapperEvent(wrapperTraceEvent{
		Operation:       "encrypt",
		Mode:            string(w.configuredMode()),
		KeyID:           blobTraceKeyID(resp.Blob),
		PlaintextBytes:  len(plaintext),
		CiphertextBytes: len(resp.Blob.GetCiphertext()),
		AADBytes:        len(opts.GetWithAad()),
	})
	return resp.Blob, nil
}

// Decrypt delegates ciphertext unwrapping to the initialized backend.
func (w *Wrapper) Decrypt(
	ctx context.Context,
	ciphertext *wrapping.BlobInfo,
	options ...wrapping.Option,
) ([]byte, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	backend, err := w.currentBackend()
	if err != nil {
		return nil, err
	}
	resp, err := backend.Decrypt(ctx, DecryptRequest{
		Blob:  ciphertext,
		AAD:   opts.GetWithAad(),
		KeyID: opts.GetWithKeyId(),
	})
	if err != nil {
		return nil, err
	}
	traceWrapperEvent(wrapperTraceEvent{
		Operation:       "decrypt",
		Mode:            string(w.configuredMode()),
		KeyID:           blobTraceKeyID(ciphertext),
		PlaintextBytes:  len(resp.Plaintext),
		CiphertextBytes: len(ciphertext.GetCiphertext()),
		AADBytes:        len(opts.GetWithAad()),
	})
	return resp.Plaintext, nil
}

// KeyId returns the active key ID known to the initialized backend.
func (w *Wrapper) KeyId(ctx context.Context) (string, error) {
	backend, err := w.currentBackend()
	if err != nil {
		return "", err
	}
	return backend.KeyID(ctx)
}

// Finalize closes backend resources.
func (w *Wrapper) Finalize(ctx context.Context, _ ...wrapping.Option) error {
	w.mu.Lock()
	backend := w.backend
	w.backend = nil
	w.mu.Unlock()

	if backend == nil {
		return nil
	}
	return backend.Close(ctx)
}

func (w *Wrapper) currentBackend() (Backend, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.backend == nil {
		return nil, ErrNotInitialized
	}
	return w.backend, nil
}

func (w *Wrapper) configuredMode() Mode {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.config.Mode
}

func (w *Wrapper) newBackendLocked(ctx context.Context, config Config) (Backend, error) {
	if w.factory == nil {
		return nil, fmt.Errorf("%w: backend factory is missing", ErrBackendUnavailable)
	}
	return w.factory.NewBackend(ctx, config)
}
