package kmsplugin

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	configKeyMode          = "mode"
	configKeyBrokerAddress = "broker_addr"
	configKeyClusterID     = "cluster_id"
	configKeyKeyID         = "key_id"
	configKeyKeyVersion    = "key_version"
	configKeyPolicyID      = "policy_id"
	configKeyStatePath     = "state_path"
	configKeyTPMDevice     = "tpm_device"
)

// Mode selects the configured wrapper backend.
type Mode string

const (
	// ModeBroker delegates wrapping operations to the internal-network broker.
	ModeBroker Mode = "broker"
	// ModeLocalTPM unwraps the local key through a TPM sealed object.
	ModeLocalTPM Mode = "local-tpm"
)

// Config is the strict wrapper configuration parsed from OpenBao seal config.
type Config struct {
	Mode          Mode
	BrokerAddress string
	ClusterID     string
	KeyID         string
	KeyVersion    uint32
	PolicyID      string
	StatePath     string
	TPMDevice     string
}

func parseConfig(values map[string]string) (Config, error) {
	for key := range values {
		if !knownConfigKey(key) {
			return Config{}, fmt.Errorf("unknown attested unseal config key %q: %w", key, wrappingConfigError())
		}
	}

	config := Config{
		Mode:          Mode(strings.TrimSpace(values[configKeyMode])),
		BrokerAddress: strings.TrimSpace(values[configKeyBrokerAddress]),
		ClusterID:     strings.TrimSpace(values[configKeyClusterID]),
		KeyID:         strings.TrimSpace(values[configKeyKeyID]),
		PolicyID:      strings.TrimSpace(values[configKeyPolicyID]),
		StatePath:     strings.TrimSpace(values[configKeyStatePath]),
		TPMDevice:     strings.TrimSpace(values[configKeyTPMDevice]),
	}
	if raw := strings.TrimSpace(values[configKeyKeyVersion]); raw != "" {
		version, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return Config{}, fmt.Errorf("invalid key_version: %w", wrappingConfigError())
		}
		config.KeyVersion = uint32(version)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// Validate checks that required backend configuration is present.
func (c Config) Validate() error {
	switch c.Mode {
	case ModeBroker:
		if c.BrokerAddress == "" {
			return fmt.Errorf("broker_addr is required: %w", wrappingConfigError())
		}
	case ModeLocalTPM:
		if c.StatePath == "" {
			return fmt.Errorf("state_path is required: %w", wrappingConfigError())
		}
		if c.KeyID == "" || c.KeyVersion == 0 {
			return fmt.Errorf("key_id and key_version are required for local-tpm: %w", wrappingConfigError())
		}
	default:
		return fmt.Errorf("mode must be %q or %q: %w", ModeBroker, ModeLocalTPM, wrappingConfigError())
	}
	if err := keyring.ValidateIdentifier(c.ClusterID); err != nil {
		return fmt.Errorf("invalid cluster_id: %w", err)
	}
	if c.KeyID != "" {
		if err := keyring.ValidateIdentifier(c.KeyID); err != nil {
			return fmt.Errorf("invalid key_id: %w", err)
		}
	}
	if c.PolicyID != "" {
		if err := keyring.ValidateIdentifier(c.PolicyID); err != nil {
			return fmt.Errorf("invalid policy_id: %w", err)
		}
	}
	return nil
}

// ConfiguredKeyID returns a stable key reference if the config includes one.
func (c Config) ConfiguredKeyID() string {
	if c.KeyID == "" || c.KeyVersion == 0 {
		return ""
	}
	return keyring.KeyRef{
		ClusterID: c.ClusterID,
		KeyID:     c.KeyID,
		Version:   c.KeyVersion,
	}.String()
}

func knownConfigKey(key string) bool {
	switch key {
	case configKeyMode, configKeyBrokerAddress, configKeyClusterID:
		return true
	case configKeyKeyID, configKeyKeyVersion, configKeyPolicyID:
		return true
	case configKeyStatePath, configKeyTPMDevice:
		return true
	default:
		return false
	}
}

func wrappingConfigError() error {
	return fmt.Errorf("invalid parameter: %w", wrapping.ErrInvalidParameter)
}
