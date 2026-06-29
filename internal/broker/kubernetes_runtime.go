package broker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	runtimeconfig "github.com/adfinis/openbao-attested-unseal/internal/config"
)

type runtimeServiceDependencies struct {
	Service      *Service
	NodeEvidence NodeEvidenceStore
}

func newRuntimeService(
	config Config,
	store Store,
	audit *FileAuditSink,
	telemetry *Telemetry,
) (runtimeServiceDependencies, error) {
	if !config.Kubernetes.Enabled {
		return runtimeServiceDependencies{
			Service: NewService(config, store, audit, telemetry),
		}, nil
	}
	kubernetesDeps, err := newKubernetesRuntimeDependencies(config.Kubernetes)
	if err != nil {
		return runtimeServiceDependencies{}, err
	}
	service := NewServiceWithEvidenceVerifierAndNodeEvidence(
		config,
		store,
		audit,
		telemetry,
		kubernetesDeps.verifier,
		store,
	)
	return runtimeServiceDependencies{
		Service:      service,
		NodeEvidence: store,
	}, nil
}

type kubernetesRuntimeDependencies struct {
	verifier KubernetesEvidenceVerifier
}

func newKubernetesRuntimeDependencies(config KubernetesConfig) (kubernetesRuntimeDependencies, error) {
	endpoint, err := runtimeconfig.KubernetesAPIServer(config.APIServer)
	if err != nil {
		return kubernetesRuntimeDependencies{}, err
	}
	token, err := readKubernetesBearerToken(config.BearerTokenFile)
	if err != nil {
		return kubernetesRuntimeDependencies{}, err
	}
	httpClient, err := newKubernetesHTTPClient(config)
	if err != nil {
		return kubernetesRuntimeDependencies{}, err
	}
	reviewer := k8sprovider.HTTPTokenReviewClient{
		Endpoint:    endpoint,
		BearerToken: token,
		HTTPClient:  httpClient,
	}
	var podLookup k8sprovider.PodLookup
	if config.RequirePodBoundToken() {
		podLookup = k8sprovider.HTTPPodLookupClient{
			Endpoint:    endpoint,
			BearerToken: token,
			HTTPClient:  httpClient,
		}
	}
	return kubernetesRuntimeDependencies{
		verifier: NewKubernetesEvidenceVerifierWithPodLookup(reviewer, podLookup, config),
	}, nil
}

func readKubernetesBearerToken(path string) (string, error) {
	path = runtimeconfig.KubernetesBearerTokenFile(path)
	// #nosec G304 -- Kubernetes bearer token file path is operator supplied broker configuration.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Kubernetes bearer token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("kubernetes bearer token file is empty")
	}
	return token, nil
}

func newKubernetesHTTPClient(config KubernetesConfig) (*http.Client, error) {
	client := &http.Client{Timeout: config.APITimeout()}
	caFile := runtimeconfig.KubernetesCAFile(config.CACertFile)
	if caFile == "" {
		return client, nil
	}
	// #nosec G304 -- Kubernetes CA file path is operator supplied broker configuration.
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("kubernetes CA file does not contain certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	client.Transport = transport
	return client, nil
}
