// Package broker implements the bao-unseald broker skeleton.
package broker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
)

const (
	// DefaultChallengeTTL is used when the config omits challenge_ttl_seconds.
	DefaultChallengeTTL = 2 * time.Minute
	// DefaultKubernetesNodeEvidenceTTL is used when Kubernetes config omits node_evidence_ttl_seconds.
	DefaultKubernetesNodeEvidenceTTL = 5 * time.Minute
	// DefaultKubernetesAPITimeout is used when Kubernetes config omits api_timeout_seconds.
	DefaultKubernetesAPITimeout = 10 * time.Second
	// DevelopmentProfile is the only keyring profile implemented by the M2 skeleton.
	DevelopmentProfile = "development"
	// OTelExporterNone disables SDK exporter setup while preserving instrumentation hooks.
	OTelExporterNone = "none"
	// OTelExporterStdout emits traces and metrics as JSON to stdout.
	OTelExporterStdout = "stdout"
	// PolicyModeDevelopmentSubject is the only default policy document mode in M2.
	PolicyModeDevelopmentSubject = "development-subject"
)

// Config describes one broker daemon instance.
type Config struct {
	ListenAddress             string           `json:"listen_address"`
	TLSCertFile               string           `json:"tls_cert_file"`
	TLSKeyFile                string           `json:"tls_key_file"`
	ClientCAFile              string           `json:"client_ca_file"`
	RequireClientCert         bool             `json:"require_client_cert"`
	AllowPlaintextForTests    bool             `json:"allow_plaintext_for_tests"`
	SQLitePath                string           `json:"sqlite_path"`
	AuditFilePath             string           `json:"audit_file_path"`
	AuditFsync                bool             `json:"audit_fsync"`
	OTelExporter              string           `json:"otel_exporter"`
	DefaultPolicyPath         string           `json:"default_policy_path"`
	KeyringProtectionProfile  string           `json:"keyring_protection_profile"`
	ClusterID                 string           `json:"cluster_id"`
	KeyID                     string           `json:"key_id"`
	PolicyID                  string           `json:"policy_id"`
	DevelopmentSubject        string           `json:"development_subject"`
	DevelopmentWrappingKeyB64 string           `json:"development_wrapping_key_b64"`
	ChallengeTTLSeconds       int64            `json:"challenge_ttl_seconds"`
	Kubernetes                KubernetesConfig `json:"kubernetes"`
	DefaultPolicy             PolicyDocument   `json:"-"`
}

// KubernetesConfig contains the optional Kubernetes workload verifier configuration.
type KubernetesConfig struct {
	Enabled                          bool   `json:"enabled"`
	APIServer                        string `json:"api_server"`
	CACertFile                       string `json:"ca_cert_file"`
	BearerTokenFile                  string `json:"bearer_token_file"`
	TokenReviewAudience              string `json:"token_review_audience"`
	Namespace                        string `json:"namespace"`
	ServiceAccount                   string `json:"service_account"`
	NodeEvidenceTTLSeconds           int64  `json:"node_evidence_ttl_seconds"`
	APITimeoutSeconds                int64  `json:"api_timeout_seconds"`
	AllowUnboundServiceAccountTokens bool   `json:"allow_unbound_service_account_tokens"`
	AllowFakeNodeEvidencePublish     bool   `json:"allow_fake_node_evidence_publish"`
}

// PolicyDocument is the M2 default policy file format.
type PolicyDocument struct {
	PolicyID            string   `json:"policy_id"`
	Mode                string   `json:"mode"`
	DevelopmentSubjects []string `json:"development_subjects"`
}

// LoadConfig reads a JSON broker config file.
func LoadConfig(path string) (Config, error) {
	// #nosec G304 -- broker config path is operator supplied.
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read broker config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(raw, &config); err != nil {
		return Config{}, fmt.Errorf("parse broker config: %w", err)
	}
	config, err = config.WithLoadedPolicy()
	if err != nil {
		return Config{}, err
	}
	return config, config.Validate()
}

// WithLoadedPolicy loads the optional default policy document.
func (c Config) WithLoadedPolicy() (Config, error) {
	path := strings.TrimSpace(c.DefaultPolicyPath)
	if path == "" {
		return c, nil
	}
	policy, err := LoadPolicyDocument(path)
	if err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(c.PolicyID) != "" && c.PolicyID != policy.PolicyID {
		return Config{}, fmt.Errorf(
			"policy_id %q does not match default policy file policy_id %q",
			c.PolicyID,
			policy.PolicyID,
		)
	}
	c.DefaultPolicy = policy
	return c, nil
}

// LoadPolicyDocument reads and validates an M2 default policy document.
func LoadPolicyDocument(path string) (PolicyDocument, error) {
	// #nosec G304 -- policy path is operator supplied broker configuration.
	raw, err := os.ReadFile(path)
	if err != nil {
		return PolicyDocument{}, fmt.Errorf("read default policy: %w", err)
	}
	var policy PolicyDocument
	if err := json.Unmarshal(raw, &policy); err != nil {
		return PolicyDocument{}, fmt.Errorf("parse default policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return PolicyDocument{}, err
	}
	return policy, nil
}

// Validate checks static broker configuration.
func (c Config) Validate() error {
	validators := []func() error{
		c.validateRequiredPaths,
		c.validateTLS,
		c.validateIdentifiers,
		c.validateModes,
		c.validateDefaultPolicy,
		c.validateDevelopment,
		c.validateChallengeTTL,
		c.validateKubernetes,
	}
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateRequiredPaths() error {
	if strings.TrimSpace(c.ListenAddress) == "" {
		return errors.New("listen_address is required")
	}
	if strings.TrimSpace(c.SQLitePath) == "" {
		return errors.New("sqlite_path is required")
	}
	if strings.TrimSpace(c.AuditFilePath) == "" {
		return errors.New("audit_file_path is required")
	}
	return nil
}

func (c Config) validateTLS() error {
	if !c.AllowPlaintextForTests {
		if strings.TrimSpace(c.TLSCertFile) == "" {
			return errors.New("tls_cert_file is required unless plaintext is explicitly allowed for tests")
		}
		if strings.TrimSpace(c.TLSKeyFile) == "" {
			return errors.New("tls_key_file is required unless plaintext is explicitly allowed for tests")
		}
	}
	if c.RequireClientCert && strings.TrimSpace(c.ClientCAFile) == "" {
		return errors.New("client_ca_file is required when require_client_cert is true")
	}
	return nil
}

func (c Config) validateIdentifiers() error {
	if err := keyring.ValidateIdentifier(c.ClusterID); err != nil {
		return fmt.Errorf("invalid cluster_id: %w", err)
	}
	if err := keyring.ValidateIdentifier(c.KeyID); err != nil {
		return fmt.Errorf("invalid key_id: %w", err)
	}
	if err := keyring.ValidateIdentifier(c.Policy()); err != nil {
		return fmt.Errorf("invalid policy_id: %w", err)
	}
	return nil
}

func (c Config) validateModes() error {
	if profile := c.Profile(); profile != DevelopmentProfile {
		return fmt.Errorf("unsupported keyring_protection_profile %q", profile)
	}
	switch exporter := c.Exporter(); exporter {
	case OTelExporterNone, OTelExporterStdout:
	default:
		return fmt.Errorf("unsupported otel_exporter %q", exporter)
	}
	return nil
}

func (c Config) validateDefaultPolicy() error {
	if strings.TrimSpace(c.DefaultPolicyPath) == "" {
		return nil
	}
	if c.DefaultPolicy.PolicyID == "" {
		return errors.New("default_policy_path must be loaded before validation")
	}
	return c.DefaultPolicy.Validate()
}

func (c Config) validateDevelopment() error {
	subjects := c.DevelopmentSubjects()
	for _, subject := range subjects {
		if err := keyring.ValidateIdentifier(subject); err != nil {
			return fmt.Errorf("invalid development subject %q: %w", subject, err)
		}
	}
	if len(subjects) > 0 {
		if _, err := c.DevelopmentWrappingKey(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateChallengeTTL() error {
	if c.ChallengeTTL() <= 0 {
		return errors.New("challenge_ttl_seconds must be greater than zero")
	}
	return nil
}

func (c Config) validateKubernetes() error {
	kubernetes := c.Kubernetes
	if !kubernetes.Enabled {
		if kubernetes.NodeEvidenceTTLSeconds < 0 {
			return errors.New("kubernetes.node_evidence_ttl_seconds must not be negative")
		}
		if kubernetes.APITimeoutSeconds < 0 {
			return errors.New("kubernetes.api_timeout_seconds must not be negative")
		}
		return nil
	}
	if strings.TrimSpace(kubernetes.TokenReviewAudience) == "" {
		return errors.New("kubernetes.token_review_audience is required when kubernetes is enabled")
	}
	if strings.TrimSpace(kubernetes.Namespace) == "" {
		return errors.New("kubernetes.namespace is required when kubernetes is enabled")
	}
	if err := keyring.ValidateIdentifier(strings.TrimSpace(kubernetes.Namespace)); err != nil {
		return fmt.Errorf("invalid kubernetes.namespace: %w", err)
	}
	if strings.TrimSpace(kubernetes.ServiceAccount) == "" {
		return errors.New("kubernetes.service_account is required when kubernetes is enabled")
	}
	if err := keyring.ValidateIdentifier(strings.TrimSpace(kubernetes.ServiceAccount)); err != nil {
		return fmt.Errorf("invalid kubernetes.service_account: %w", err)
	}
	if kubernetes.NodeEvidenceTTL() <= 0 {
		return errors.New("kubernetes.node_evidence_ttl_seconds must be greater than zero")
	}
	if kubernetes.APITimeout() <= 0 {
		return errors.New("kubernetes.api_timeout_seconds must be greater than zero")
	}
	return nil
}

// ChallengeTTL returns the configured challenge TTL.
func (c Config) ChallengeTTL() time.Duration {
	if c.ChallengeTTLSeconds == 0 {
		return DefaultChallengeTTL
	}
	return time.Duration(c.ChallengeTTLSeconds) * time.Second
}

// NodeEvidenceTTL returns the configured Kubernetes node evidence freshness window.
func (k KubernetesConfig) NodeEvidenceTTL() time.Duration {
	if k.NodeEvidenceTTLSeconds == 0 {
		return DefaultKubernetesNodeEvidenceTTL
	}
	return time.Duration(k.NodeEvidenceTTLSeconds) * time.Second
}

// APITimeout returns the configured Kubernetes API request timeout.
func (k KubernetesConfig) APITimeout() time.Duration {
	if k.APITimeoutSeconds == 0 {
		return DefaultKubernetesAPITimeout
	}
	return time.Duration(k.APITimeoutSeconds) * time.Second
}

// RequirePodBoundToken returns whether Kubernetes evidence must include pod-bound token claims.
func (k KubernetesConfig) RequirePodBoundToken() bool {
	return !k.AllowUnboundServiceAccountTokens
}

// Profile returns the configured keyring protection profile.
func (c Config) Profile() string {
	if strings.TrimSpace(c.KeyringProtectionProfile) == "" {
		return DevelopmentProfile
	}
	return strings.TrimSpace(c.KeyringProtectionProfile)
}

// Policy returns the configured default policy ID.
func (c Config) Policy() string {
	if strings.TrimSpace(c.DefaultPolicy.PolicyID) != "" {
		return strings.TrimSpace(c.DefaultPolicy.PolicyID)
	}
	if strings.TrimSpace(c.PolicyID) == "" {
		return "development"
	}
	return strings.TrimSpace(c.PolicyID)
}

// Exporter returns the configured OpenTelemetry exporter mode.
func (c Config) Exporter() string {
	if strings.TrimSpace(c.OTelExporter) == "" {
		return OTelExporterNone
	}
	return strings.TrimSpace(c.OTelExporter)
}

// DevelopmentSubjects returns explicitly allowed development policy subjects.
func (c Config) DevelopmentSubjects() []string {
	seen := make(map[string]struct{})
	subjects := make([]string, 0, len(c.DefaultPolicy.DevelopmentSubjects)+1)
	add := func(subject string) {
		subject = strings.TrimSpace(subject)
		if subject == "" {
			return
		}
		if _, ok := seen[subject]; ok {
			return
		}
		seen[subject] = struct{}{}
		subjects = append(subjects, subject)
	}
	add(c.DevelopmentSubject)
	for _, subject := range c.DefaultPolicy.DevelopmentSubjects {
		add(subject)
	}
	slices.Sort(subjects)
	return subjects
}

// DevelopmentWrappingKey decodes the development wrapping key seed.
func (c Config) DevelopmentWrappingKey() ([]byte, error) {
	raw := strings.TrimSpace(c.DevelopmentWrappingKeyB64)
	if raw == "" {
		return nil, errors.New("development_wrapping_key_b64 is required when development_subject is configured")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode development_wrapping_key_b64: %w", err)
	}
	if len(key) != keyring.KeySize {
		return nil, fmt.Errorf("development_wrapping_key_b64 must decode to %d bytes", keyring.KeySize)
	}
	return key, nil
}

// Validate checks a default policy document.
func (p PolicyDocument) Validate() error {
	if err := keyring.ValidateIdentifier(p.PolicyID); err != nil {
		return fmt.Errorf("invalid default policy policy_id: %w", err)
	}
	if p.Mode != PolicyModeDevelopmentSubject {
		return fmt.Errorf("unsupported default policy mode %q", p.Mode)
	}
	if len(p.DevelopmentSubjects) == 0 {
		return errors.New("default policy development_subjects must not be empty")
	}
	for _, subject := range p.DevelopmentSubjects {
		if err := keyring.ValidateIdentifier(subject); err != nil {
			return fmt.Errorf("invalid default policy development subject %q: %w", subject, err)
		}
	}
	return nil
}
