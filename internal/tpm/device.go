package tpm

import (
	"context"
	"fmt"
	"io"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

const DefaultDevicePath = "/dev/tpmrm0"

// Device opens a TPM 2.0 resource manager device or Unix socket.
type Device struct {
	Path string
}

// Open opens a TPM connection. An empty path uses go-tpm's Linux defaults.
func (d Device) Open(ctx context.Context) (io.ReadWriteCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var (
		rwc io.ReadWriteCloser
		err error
	)
	if d.Path == "" {
		rwc, err = legacytpm2.OpenTPM()
	} else {
		rwc, err = legacytpm2.OpenTPM(d.Path)
	}
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = rwc.Close()
		return nil, err
	}
	return rwc, nil
}
