package broker

import (
	"strings"
	"testing"
)

func TestConfigValidateAcceptsDefaultDisabledKubernetes(t *testing.T) {
	config := validBrokerConfig()
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got := config.Kubernetes.NodeEvidenceTTL(); got != DefaultKubernetesNodeEvidenceTTL {
		t.Fatalf("NodeEvidenceTTL = %s, want %s", got, DefaultKubernetesNodeEvidenceTTL)
	}
}

func TestConfigValidateAcceptsEnabledKubernetes(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:                true,
		TokenReviewAudience:    "bao-unseald",
		Namespace:              "openbao",
		ServiceAccount:         "openbao",
		NodeEvidenceTTLSeconds: 30,
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got := config.Kubernetes.NodeEvidenceTTL().Seconds(); got != 30 {
		t.Fatalf("NodeEvidenceTTL seconds = %.0f, want 30", got)
	}
	if !config.Kubernetes.RequirePodBoundToken() {
		t.Fatal("RequirePodBoundToken = false, want true")
	}
}

func TestConfigValidateRejectsIncompleteKubernetes(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:        true,
		Namespace:      "openbao",
		ServiceAccount: "openbao",
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "token_review_audience") {
		t.Fatalf("Validate error = %v, want token_review_audience error", err)
	}
}

func TestConfigValidateRejectsInvalidKubernetesTTL(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:                true,
		TokenReviewAudience:    "bao-unseald",
		Namespace:              "openbao",
		ServiceAccount:         "openbao",
		NodeEvidenceTTLSeconds: -1,
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "node_evidence_ttl_seconds") {
		t.Fatalf("Validate error = %v, want node_evidence_ttl_seconds error", err)
	}
}

func validBrokerConfig() Config {
	return Config{
		ListenAddress:             "127.0.0.1:8443",
		AllowPlaintextForTests:    true,
		SQLitePath:                "broker.db",
		AuditFilePath:             "audit.jsonl",
		KeyringProtectionProfile:  DevelopmentProfile,
		OTelExporter:              OTelExporterNone,
		ClusterID:                 "prod-eu1",
		KeyID:                     "root",
		PolicyID:                  "development",
		DevelopmentSubject:        "node-a",
		DevelopmentWrappingKeyB64: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		ChallengeTTLSeconds:       60,
	}
}
