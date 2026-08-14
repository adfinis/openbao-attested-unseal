package broker

import (
	"strings"
	"testing"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
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

func TestConfigValidateRejectsEmptyNodeEvidenceProvider(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes = KubernetesConfig{
		Enabled:                      true,
		TokenReviewAudience:          "bao-unseald",
		Namespace:                    "openbao",
		ServiceAccount:               "openbao",
		NodeEvidencePublishProviders: []string{"generic-tpm2-quote", " "},
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "node_evidence_publish_providers") {
		t.Fatalf("Validate error = %v, want node_evidence_publish_providers error", err)
	}
}

func TestConfigValidateRejectsUnknownNodeEvidenceProvider(t *testing.T) {
	config := validBrokerConfig()
	config.Kubernetes.NodeEvidencePublishProviders = []string{"publisher-asserted-hash"}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported kubernetes node evidence publish provider") {
		t.Fatalf("Validate error = %v, want unsupported provider error", err)
	}
}

func TestConfigValidateAcceptsTPMProviderWithNodeEvidenceAdmin(t *testing.T) {
	config := validBrokerConfig()
	configureMutualTLS(&config)
	config.Kubernetes.NodeEvidencePublishProviders = []string{nodeevidence.ProviderTPM2Quote}
	config.ControlPlane.Identities = map[string]ControlPlaneIdentity{
		"sha256:" + strings.Repeat("cd", 32): {
			Roles:      []string{ControlPlaneRoleNodeEvidenceAdmin},
			ClusterIDs: []string{config.ClusterID},
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
}

func TestConfigValidateRejectsTPMProviderWithoutNodeEvidenceAdmin(t *testing.T) {
	config := validBrokerConfig()
	configureMutualTLS(&config)
	config.Kubernetes.NodeEvidencePublishProviders = []string{nodeevidence.ProviderTPM2Quote}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "node-evidence-admin") {
		t.Fatalf("Validate error = %v, want node-evidence-admin error", err)
	}
}

func TestConfigValidateRejectsControlPlaneIdentityWithoutMutualTLS(t *testing.T) {
	config := validBrokerConfig()
	config.ControlPlane.Identities = map[string]ControlPlaneIdentity{
		"sha256:" + strings.Repeat("cd", 32): {
			Roles:      []string{ControlPlaneRoleNodeEvidenceAdmin},
			ClusterIDs: []string{config.ClusterID},
		},
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "plaintext transport") {
		t.Fatalf("Validate error = %v, want plaintext transport error", err)
	}
}

func TestConfigValidateRejectsNonCanonicalControlPlaneIdentity(t *testing.T) {
	config := validBrokerConfig()
	configureMutualTLS(&config)
	config.ControlPlane.Identities = map[string]ControlPlaneIdentity{
		"sha256:" + strings.Repeat("CD", 32): {
			Roles:      []string{ControlPlaneRoleNodeEvidenceAdmin},
			ClusterIDs: []string{config.ClusterID},
		},
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "non-canonical certificate") {
		t.Fatalf("Validate error = %v, want canonical certificate error", err)
	}
}

func TestConfigValidateRejectsUnsupportedControlPlaneRole(t *testing.T) {
	config := validBrokerConfig()
	configureMutualTLS(&config)
	config.ControlPlane.Identities = map[string]ControlPlaneIdentity{
		"sha256:" + strings.Repeat("cd", 32): {
			Roles:      []string{"superuser"},
			ClusterIDs: []string{config.ClusterID},
		},
	}

	err := config.Validate()
	if err == nil || !strings.Contains(err.Error(), "unsupported role") {
		t.Fatalf("Validate error = %v, want unsupported role error", err)
	}
}

func TestRejectDeprecatedStaticNodeTrustConfig(t *testing.T) {
	err := rejectDeprecatedNodeTrustConfig([]byte(`{
		"kubernetes": {
			"node_evidence_tpm_policies": {},
			"node_evidence_publishers": {}
		}
	}`))
	if err == nil || !strings.Contains(err.Error(), "authenticated node enrollment") {
		t.Fatalf("deprecated config error = %v, want replacement guidance", err)
	}
}

func configureMutualTLS(config *Config) {
	config.AllowPlaintextForTests = false
	config.TLSCertFile = "server.crt"
	config.TLSKeyFile = "server.key"
	config.RequireClientCert = true
	config.ClientCAFile = "client-ca.crt"
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
