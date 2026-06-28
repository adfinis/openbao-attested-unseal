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
		configKeyMode:          string(ModeBroker),
		configKeyBrokerAddress: "unix:///run/bao-unseald/broker.sock",
		configKeyClusterID:     "prod-eu1",
		configKeyKeyID:         "root",
		configKeyKeyVersion:    "7",
		configKeyPolicyID:      "secureboot",
	})
	if err != nil {
		t.Fatalf("parseConfig returned error: %v", err)
	}
	if got := config.ConfiguredKeyID(); got != "prod-eu1/root/v7" {
		t.Fatalf("ConfiguredKeyID() = %q, want prod-eu1/root/v7", got)
	}
}
