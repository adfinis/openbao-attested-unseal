package broker

import (
	"fmt"

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
