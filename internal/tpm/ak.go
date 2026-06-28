package tpm

import (
	"fmt"
	"io"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const defaultAKAuth = ""

// AK is a loaded attestation key.
type AK struct {
	Handle tpmutil.Handle
	Public []byte
	Name   []byte
	auth   string
}

// Flush removes the loaded AK from TPM transient memory.
func (a AK) Flush(rw io.ReadWriter) error {
	if a.Handle == 0 {
		return nil
	}
	return legacytpm2.FlushContext(rw, a.Handle)
}

// CreateAK creates an ephemeral RSA attestation key under the owner hierarchy.
func CreateAK(rw io.ReadWriter) (AK, error) {
	handle, public, _, _, _, name, err := legacytpm2.CreatePrimaryEx(
		rw,
		legacytpm2.HandleOwner,
		legacytpm2.PCRSelection{},
		"",
		defaultAKAuth,
		akTemplate(),
	)
	if err != nil {
		return AK{}, fmt.Errorf("create AK: %w", err)
	}
	return AK{
		Handle: handle,
		Public: public,
		Name:   name,
		auth:   defaultAKAuth,
	}, nil
}

func akTemplate() legacytpm2.Public {
	return legacytpm2.Public{
		Type:       legacytpm2.AlgRSA,
		NameAlg:    legacytpm2.AlgSHA256,
		Attributes: legacytpm2.FlagSignerDefault | legacytpm2.FlagNoDA,
		RSAParameters: &legacytpm2.RSAParams{
			Sign: &legacytpm2.SigScheme{
				Alg:  legacytpm2.AlgRSASSA,
				Hash: legacytpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}
}
