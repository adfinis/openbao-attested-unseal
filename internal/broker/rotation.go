package broker

import (
	"errors"
	"fmt"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

func validateRotationStart(request RotationStartRequest) error {
	if request.OperationID == "" {
		return fmt.Errorf("%w: operation_id is required", ErrRotationInvalidTransition)
	}
	if err := keyring.ValidateIdentifier(request.ClusterID); err != nil {
		return fmt.Errorf("%w: invalid cluster_id", err)
	}
	if err := keyring.ValidateIdentifier(request.KeyID); err != nil {
		return fmt.Errorf("%w: invalid key_id", err)
	}
	if err := keyring.ValidateIdentifier(request.PolicyID); err != nil {
		return fmt.Errorf("%w: invalid policy_id", err)
	}
	if len(request.Material) != keyring.KeySize {
		return fmt.Errorf("%w: key material must be %d bytes", keyring.ErrInvalidMetadata, keyring.KeySize)
	}
	return nil
}

func validateRotationVerification(name RotationVerificationName, detail string) error {
	switch name {
	case RotationVerificationOpenBAORoot, RotationVerificationRestart, RotationVerificationKeyVersion:
	default:
		return fmt.Errorf("%w: unsupported rotation verification %q", ErrRotationInvalidTransition, name)
	}
	if strings.TrimSpace(detail) == "" {
		return errors.New("rotation verification detail is required")
	}
	return nil
}
