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
	if got := config.Kubernetes.NodeEvidenceRetention(); got != DefaultKubernetesNodeEvidenceRetention {
		t.Fatalf("NodeEvidenceRetention = %s, want %s", got, DefaultKubernetesNodeEvidenceRetention)
	}
}

func TestConfigValidateAcceptsEnabledKubernetes(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:                      true,
		APIServer:                    "https://kubernetes.default.svc",
		TokenReviewAudience:          "bao-unseald",
		Namespace:                    "openbao",
		ServiceAccount:               "openbao",
		NodeEvidenceTTLSeconds:       30,
		NodeEvidenceRetentionSeconds: 3600,
		APITimeoutSeconds:            5,
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got := config.Kubernetes.NodeEvidenceTTL().Seconds(); got != 30 {
		t.Fatalf("NodeEvidenceTTL seconds = %.0f, want 30", got)
	}
	if got := config.Kubernetes.NodeEvidenceRetention().Seconds(); got != 3600 {
		t.Fatalf("NodeEvidenceRetention seconds = %.0f, want 3600", got)
	}
	if !config.Kubernetes.RequirePodBoundToken() {
		t.Fatal("RequirePodBoundToken = false, want true")
	}
	if got := config.Kubernetes.APITimeout().Seconds(); got != 5 {
		t.Fatalf("APITimeout seconds = %.0f, want 5", got)
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

func TestConfigValidateRejectsInvalidKubernetesRetention(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:                      true,
		TokenReviewAudience:          "bao-unseald",
		Namespace:                    "openbao",
		ServiceAccount:               "openbao",
		NodeEvidenceRetentionSeconds: -1,
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "node_evidence_retention_seconds") {
		t.Fatalf("Validate error = %v, want node_evidence_retention_seconds error", err)
	}
}

func TestConfigValidateRejectsInvalidKubernetesAPITimeout(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:             true,
		TokenReviewAudience: "bao-unseald",
		Namespace:           "openbao",
		ServiceAccount:      "openbao",
		APITimeoutSeconds:   -1,
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "api_timeout_seconds") {
		t.Fatalf("Validate error = %v, want api_timeout_seconds error", err)
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
