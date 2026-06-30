package config

import (
	"strings"
	"testing"
)

func TestKubernetesAPIServerPrefersExplicit(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	endpoint, err := KubernetesAPIServer(" https://kubernetes.example.test ")
	if err != nil {
		t.Fatalf("KubernetesAPIServer returned error: %v", err)
	}
	if endpoint != "https://kubernetes.example.test" {
		t.Fatalf("endpoint = %q, want explicit endpoint", endpoint)
	}
}

func TestKubernetesAPIServerDerivesInClusterEndpoint(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "fd00::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")

	endpoint, err := KubernetesAPIServer("")
	if err != nil {
		t.Fatalf("KubernetesAPIServer returned error: %v", err)
	}
	if endpoint != "https://[fd00::1]:6443" {
		t.Fatalf("endpoint = %q, want IPv6 endpoint", endpoint)
	}
}

func TestKubernetesAPIServerUsesDefaultPort(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	endpoint, err := KubernetesAPIServer("")
	if err != nil {
		t.Fatalf("KubernetesAPIServer returned error: %v", err)
	}
	if endpoint != "https://kubernetes.default.svc:443" {
		t.Fatalf("endpoint = %q, want default port endpoint", endpoint)
	}
}

func TestKubernetesAPIServerRejectsMissingHost(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	_, err := KubernetesAPIServer("")
	if err == nil || !strings.Contains(err.Error(), "api_server") {
		t.Fatalf("KubernetesAPIServer error = %v, want api_server error", err)
	}
}

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("BAO_TEST_VALUE", " explicit ")
	if got := EnvOrDefault("BAO_TEST_VALUE", "fallback"); got != "explicit" {
		t.Fatalf("EnvOrDefault explicit = %q, want trimmed value", got)
	}
	t.Setenv("BAO_TEST_EMPTY", " ")
	if got := EnvOrDefault("BAO_TEST_EMPTY", "fallback"); got != "fallback" {
		t.Fatalf("EnvOrDefault empty = %q, want fallback", got)
	}
}
