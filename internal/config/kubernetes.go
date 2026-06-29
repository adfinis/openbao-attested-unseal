// Package config contains process-environment configuration boundary helpers.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	// KubernetesServiceAccountTokenPath is the default in-cluster bearer token path.
	KubernetesServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- path only.
	// KubernetesServiceAccountCAPath is the default in-cluster Kubernetes CA path.
	KubernetesServiceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// KubernetesAPIServer returns an explicit API server or derives the in-cluster API endpoint.
func KubernetesAPIServer(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	if host == "" {
		return "", errors.New("kubernetes.api_server is required outside an in-cluster environment")
	}
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if port == "" {
		port = "443"
	}
	return fmt.Sprintf("https://%s", net.JoinHostPort(host, port)), nil
}

// KubernetesBearerTokenFile returns an explicit token path or the default service account token path.
func KubernetesBearerTokenFile(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	return KubernetesServiceAccountTokenPath
}

// KubernetesCAFile returns an explicit CA path or the mounted service account CA path when present.
func KubernetesCAFile(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit)
	}
	if _, err := os.Stat(KubernetesServiceAccountCAPath); err == nil {
		return KubernetesServiceAccountCAPath
	}
	return ""
}
