package kmsplugin

import (
	"errors"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestParseConfigRejectsMissingMode(t *testing.T) {
	_, err := parseConfig(map[string]string{
		configKeyBrokerAddress: "unix:///run/bao-unseald/broker.sock",
		configKeyClusterID:     "prod-eu1",
	})
	if !errors.Is(err, wrapping.ErrInvalidParameter) {
		t.Fatalf("parseConfig error = %v, want ErrInvalidParameter", err)
	}
}

func TestParseConfigRejectsUnknownFields(t *testing.T) {
	_, err := parseConfig(map[string]string{
		configKeyMode:          string(ModeBroker),
		configKeyBrokerAddress: "unix:///run/bao-unseald/broker.sock",
		configKeyClusterID:     "prod-eu1",
		"surprise":             "true",
	})
	if !errors.Is(err, wrapping.ErrInvalidParameter) {
		t.Fatalf("parseConfig error = %v, want ErrInvalidParameter", err)
	}
}

func TestParseConfigAcceptsBroker(t *testing.T) {
	config, err := parseConfig(map[string]string{
		configKeyMode:            string(ModeBroker),
		configKeyBrokerAddress:   "unix:///run/bao-unseald/broker.sock",
		configKeyBrokerPlaintext: "true",
		configKeyClusterID:       "prod-eu1",
		configKeyKeyID:           "root",
		configKeyKeyVersion:      "7",
		configKeyNodeID:          "node-a",
		configKeyPolicyID:        "secureboot",
	})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if got := config.ConfiguredKeyID(); got != "prod-eu1/root/v7" {
		t.Fatalf("ConfiguredKeyID() = %q, want prod-eu1/root/v7", got)
	}
	if !config.BrokerPlaintext {
		t.Fatal("BrokerPlaintext = false, want true")
	}
	if config.BrokerEvidenceMode() != EvidenceModeDevelopmentSubject {
		t.Fatalf("BrokerEvidenceMode() = %q, want development-subject", config.BrokerEvidenceMode())
	}
}

func TestParseConfigAcceptsBrokerKubernetesEvidence(t *testing.T) {
	config, err := parseConfig(map[string]string{
		configKeyMode:          string(ModeBroker),
		configKeyBrokerAddress: "unix:///run/bao-unseald/broker.sock",
		configKeyClusterID:     "prod-eu1",
		configKeyNodeID:        "openbao.openbao",
		configKeyEvidenceMode:  string(EvidenceModeKubernetesWorkload),
	})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if config.BrokerEvidenceMode() != EvidenceModeKubernetesWorkload {
		t.Fatalf("BrokerEvidenceMode() = %q, want kubernetes-workload", config.BrokerEvidenceMode())
	}
}

func TestParseConfigRejectsUnknownBrokerEvidenceMode(t *testing.T) {
	_, err := parseConfig(map[string]string{
		configKeyMode:          string(ModeBroker),
		configKeyBrokerAddress: "unix:///run/bao-unseald/broker.sock",
		configKeyClusterID:     "prod-eu1",
		configKeyNodeID:        "node-a",
		configKeyEvidenceMode:  "surprise",
	})
	if !errors.Is(err, wrapping.ErrInvalidParameter) {
		t.Fatalf("parseConfig error = %v, want ErrInvalidParameter", err)
	}
}

func TestParseConfigAcceptsLocalTPM(t *testing.T) {
	config, err := parseConfig(map[string]string{
		configKeyMode:       string(ModeLocalTPM),
		configKeyClusterID:  "prod-eu1",
		configKeyKeyID:      "root",
		configKeyKeyVersion: "7",
		configKeyPolicyID:   "secureboot",
		configKeyStatePath:  "/var/lib/openbao/attested-unseal",
		configKeyTPMDevice:  "/dev/tpmrm0",
	})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if got := config.ConfiguredKeyID(); got != "prod-eu1/root/v7" {
		t.Fatalf("ConfiguredKeyID() = %q, want prod-eu1/root/v7", got)
	}
	if config.TPMDevice != "/dev/tpmrm0" {
		t.Fatalf("TPMDevice = %q, want /dev/tpmrm0", config.TPMDevice)
	}
}

func TestParseConfigAcceptsLocalTPMWithoutKeyVersion(t *testing.T) {
	config, err := parseConfig(map[string]string{
		configKeyMode:      string(ModeLocalTPM),
		configKeyClusterID: "prod-eu1",
		configKeyKeyID:     "root",
		configKeyStatePath: "/var/lib/openbao/attested-unseal",
		configKeyTPMDevice: "/dev/tpmrm0",
	})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if got := config.ConfiguredKeyID(); got != "" {
		t.Fatalf("ConfiguredKeyID() = %q, want empty without key_version", got)
	}
}

func TestParseConfigRejectsLocalTPMWithoutStatePath(t *testing.T) {
	_, err := parseConfig(map[string]string{
		configKeyMode:       string(ModeLocalTPM),
		configKeyClusterID:  "prod-eu1",
		configKeyKeyID:      "root",
		configKeyKeyVersion: "7",
	})
	if !errors.Is(err, wrapping.ErrInvalidParameter) {
		t.Fatalf("parseConfig error = %v, want ErrInvalidParameter", err)
	}
}
