package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrPodLookup indicates a Kubernetes Pod API transport or API failure.
var ErrPodLookup = errors.New("kubernetes pod lookup failed")

// PodInfo contains the pod scheduling facts needed for workload-to-node correlation.
type PodInfo struct {
	Namespace string
	Name      string
	UID       string
	NodeName  string
}

// PodLookup verifies pod scheduling state through the Kubernetes API.
type PodLookup interface {
	LookupPod(ctx context.Context, namespace string, name string) (PodInfo, error)
}

// HTTPPodLookupClient calls the Kubernetes core/v1 Pod API.
type HTTPPodLookupClient struct {
	Endpoint    string
	BearerToken string
	HTTPClient  *http.Client
}

// LookupPod returns the current Pod UID and scheduled node name.
func (c HTTPPodLookupClient) LookupPod(ctx context.Context, namespace string, name string) (PodInfo, error) {
	endpoint, err := podEndpoint(c.Endpoint, namespace, name)
	if err != nil {
		return PodInfo{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return PodInfo{}, fmt.Errorf("%w: create request", ErrPodLookup)
	}
	httpReq.Header.Set("Accept", "application/json")
	if strings.TrimSpace(c.BearerToken) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.BearerToken))
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return PodInfo{}, fmt.Errorf("%w: request failed", ErrPodLookup)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return PodInfo{}, fmt.Errorf("%w: API returned HTTP %d", ErrPodLookup, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, protocolMaxPayloadSize())
	var decoded podResponse
	if err := json.NewDecoder(limited).Decode(&decoded); err != nil {
		return PodInfo{}, fmt.Errorf("%w: decode response", ErrPodLookup)
	}
	return PodInfo{
		Namespace: decoded.Metadata.Namespace,
		Name:      decoded.Metadata.Name,
		UID:       decoded.Metadata.UID,
		NodeName:  decoded.Spec.NodeName,
	}, nil
}

type podResponse struct {
	Metadata podMetadata `json:"metadata,omitempty"`
	Spec     podSpec     `json:"spec,omitempty"`
}

type podMetadata struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
}

type podSpec struct {
	NodeName string `json:"nodeName,omitempty"`
}

func podEndpoint(endpoint string, namespace string, name string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if endpoint == "" {
		return "", fmt.Errorf("%w: endpoint is required", ErrPodLookup)
	}
	if namespace == "" || name == "" {
		return "", fmt.Errorf("%w: namespace and pod name are required", ErrPodLookup)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: endpoint must be an absolute URL", ErrPodLookup)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") +
		"/api/v1/namespaces/" + url.PathEscape(namespace) +
		"/pods/" + url.PathEscape(name)
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
