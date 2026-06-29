package kmsplugin

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const (
	configKeyMode                = "mode"
	configKeyBrokerAddress       = "broker_addr"
	configKeyBrokerPlaintext     = "broker_plaintext"
	configKeyBrokerCACert        = "broker_ca_cert"
	configKeyBrokerTLSServerName = "broker_tls_server_name"
	configKeyBrokerClientCert    = "broker_client_cert"
	configKeyBrokerClientKey     = "broker_client_key"
	configKeyClusterID           = "cluster_id"
	configKeyKeyID               = "key_id"
	configKeyKeyVersion          = "key_version"
	configKeyNodeID              = "node_id"
	configKeyPolicyID            = "policy_id"
	configKeyEvidenceMode        = "evidence_mode"
	configKeyKubernetesTokenFile = "kubernetes_token_file" // #nosec G101 -- config key name only.
	configKeyStatePath           = "state_path"
	configKeyTPMDevice           = "tpm_device"
)

// Mode selects the configured wrapper backend.
type Mode string

const (
	// ModeBroker delegates wrapping operations to the internal-network broker.
	ModeBroker Mode = "broker"
	// ModeLocalTPM unwraps the local key through a TPM sealed object.
	ModeLocalTPM Mode = "local-tpm"
)

// EvidenceMode selects which broker evidence envelope the plugin emits.
type EvidenceMode string

const (
	// EvidenceModeDevelopmentSubject emits the M2 development subject claim.
	EvidenceModeDevelopmentSubject EvidenceMode = "development-subject"
	// EvidenceModeKubernetesWorkload emits projected service account token evidence.
	EvidenceModeKubernetesWorkload EvidenceMode = "kubernetes-workload"
)

// Config is the strict wrapper configuration parsed from OpenBao seal config.
type Config struct {
	Mode                 Mode
	BrokerAddress        string
	BrokerPlaintext      bool
	BrokerCACertPath     string
	BrokerTLSServerName  string
	BrokerClientCertPath string
	BrokerClientKeyPath  string
	ClusterID            string
	KeyID                string
	KeyVersion           uint32
	NodeID               string
	PolicyID             string
	EvidenceMode         EvidenceMode
	KubernetesTokenFile  string
	StatePath            string
	TPMDevice            string
}

func parseConfig(values map[string]string) (Config, error) {
	for key := range values {
		if !knownConfigKey(key) {
			return Config{}, fmt.Errorf("unknown attested unseal config key %q: %w", key, wrappingConfigError())
		}
	}

	config := Config{
		Mode:                 Mode(strings.TrimSpace(values[configKeyMode])),
		BrokerAddress:        strings.TrimSpace(values[configKeyBrokerAddress]),
		BrokerCACertPath:     strings.TrimSpace(values[configKeyBrokerCACert]),
		BrokerTLSServerName:  strings.TrimSpace(values[configKeyBrokerTLSServerName]),
		BrokerClientCertPath: strings.TrimSpace(values[configKeyBrokerClientCert]),
		BrokerClientKeyPath:  strings.TrimSpace(values[configKeyBrokerClientKey]),
		ClusterID:            strings.TrimSpace(values[configKeyClusterID]),
		KeyID:                strings.TrimSpace(values[configKeyKeyID]),
		NodeID:               strings.TrimSpace(values[configKeyNodeID]),
		PolicyID:             strings.TrimSpace(values[configKeyPolicyID]),
		EvidenceMode:         EvidenceMode(strings.TrimSpace(values[configKeyEvidenceMode])),
		KubernetesTokenFile:  strings.TrimSpace(values[configKeyKubernetesTokenFile]),
		StatePath:            strings.TrimSpace(values[configKeyStatePath]),
		TPMDevice:            strings.TrimSpace(values[configKeyTPMDevice]),
	}
	if raw := strings.TrimSpace(values[configKeyBrokerPlaintext]); raw != "" {
		plaintext, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid broker_plaintext: %w", wrappingConfigError())
		}
		config.BrokerPlaintext = plaintext
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
		if err := c.validateBrokerConfig(); err != nil {
			return err
		}
	case ModeLocalTPM:
		if err := c.validateLocalTPMConfig(); err != nil {
			return err
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
	if c.NodeID != "" {
		if err := keyring.ValidateIdentifier(c.NodeID); err != nil {
			return fmt.Errorf("invalid node_id: %w", err)
		}
	}
	if c.PolicyID != "" {
		if err := keyring.ValidateIdentifier(c.PolicyID); err != nil {
			return fmt.Errorf("invalid policy_id: %w", err)
		}
	}
	return nil
}

func (c Config) validateBrokerConfig() error {
	if c.BrokerAddress == "" {
		return fmt.Errorf("broker_addr is required: %w", wrappingConfigError())
	}
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required for broker: %w", wrappingConfigError())
	}
	if (c.BrokerClientCertPath == "") != (c.BrokerClientKeyPath == "") {
		return fmt.Errorf("broker_client_cert and broker_client_key must be configured together: %w", wrappingConfigError())
	}
	return c.validateBrokerEvidenceMode()
}

func (c Config) validateLocalTPMConfig() error {
	if c.StatePath == "" {
		return fmt.Errorf("state_path is required: %w", wrappingConfigError())
	}
	if c.KeyID == "" {
		return fmt.Errorf("key_id is required for local-tpm: %w", wrappingConfigError())
	}
	return nil
}

func (c Config) validateBrokerEvidenceMode() error {
	switch c.BrokerEvidenceMode() {
	case EvidenceModeDevelopmentSubject, EvidenceModeKubernetesWorkload:
		return nil
	default:
		return fmt.Errorf("evidence_mode must be %q or %q: %w",
			EvidenceModeDevelopmentSubject,
			EvidenceModeKubernetesWorkload,
			wrappingConfigError(),
		)
	}
}

// BrokerEvidenceMode returns the configured broker evidence mode.
func (c Config) BrokerEvidenceMode() EvidenceMode {
	if c.EvidenceMode == "" {
		return EvidenceModeDevelopmentSubject
	}
	return c.EvidenceMode
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
	case configKeyBrokerPlaintext, configKeyBrokerCACert, configKeyBrokerTLSServerName:
		return true
	case configKeyBrokerClientCert, configKeyBrokerClientKey:
		return true
	case configKeyKeyID, configKeyKeyVersion, configKeyPolicyID:
		return true
	case configKeyNodeID, configKeyEvidenceMode, configKeyKubernetesTokenFile:
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
