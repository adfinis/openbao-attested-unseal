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
	if err := request.Key.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrRotationInvalidTransition, err)
	}
	if err := keyring.ValidateIdentifier(request.Key.Ref.ClusterID); err != nil {
		return fmt.Errorf("%w: invalid cluster_id", err)
	}
	if err := keyring.ValidateIdentifier(request.Key.Ref.KeyID); err != nil {
		return fmt.Errorf("%w: invalid key_id", err)
	}
	if err := keyring.ValidateIdentifier(request.Key.PolicyID); err != nil {
		return fmt.Errorf("%w: invalid policy_id", err)
	}
	if request.Key.Status != keyring.StatusPending {
		return fmt.Errorf("%w: new rotation key must be pending", ErrRotationInvalidTransition)
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
