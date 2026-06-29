package kubernetes

import (
	"bytes"
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

const tokenReviewPath = "/apis/authentication.k8s.io/v1/tokenreviews"

// ErrTokenReview indicates a Kubernetes TokenReview transport or API failure.
var ErrTokenReview = errors.New("kubernetes tokenreview failed")

// TokenReviewRequest is the broker-local TokenReview request shape.
type TokenReviewRequest struct {
	Token     string
	Audiences []string
}

// UserInfo is the authenticated Kubernetes user returned by TokenReview.
type UserInfo struct {
	Username string              `json:"username,omitempty"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

// TokenReviewStatus is the broker-local TokenReview status shape.
type TokenReviewStatus struct {
	Authenticated bool     `json:"authenticated,omitempty"`
	User          UserInfo `json:"user,omitempty"`
	Audiences     []string `json:"audiences,omitempty"`
	Error         string   `json:"error,omitempty"`
}

// TokenReviewer validates Kubernetes service account tokens.
type TokenReviewer interface {
	ReviewToken(context.Context, TokenReviewRequest) (TokenReviewStatus, error)
}

// HTTPTokenReviewClient calls the Kubernetes authentication.k8s.io TokenReview API.
type HTTPTokenReviewClient struct {
	Endpoint    string
	BearerToken string
	HTTPClient  *http.Client
}

// ReviewToken validates a workload token with the Kubernetes API.
func (c HTTPTokenReviewClient) ReviewToken(
	ctx context.Context,
	request TokenReviewRequest,
) (TokenReviewStatus, error) {
	if strings.TrimSpace(request.Token) == "" {
		return TokenReviewStatus{}, fmt.Errorf("%w: token is required", ErrTokenReview)
	}
	endpoint, err := tokenReviewEndpoint(c.Endpoint)
	if err != nil {
		return TokenReviewStatus{}, err
	}
	body, err := json.Marshal(tokenReview{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec:       tokenReviewSpec(request),
	})
	if err != nil {
		return TokenReviewStatus{}, fmt.Errorf("%w: encode request", ErrTokenReview)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return TokenReviewStatus{}, fmt.Errorf("%w: create request", ErrTokenReview)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.BearerToken) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.BearerToken))
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return TokenReviewStatus{}, fmt.Errorf("%w: request failed", ErrTokenReview)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return TokenReviewStatus{}, fmt.Errorf("%w: API returned HTTP %d", ErrTokenReview, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, protocolMaxPayloadSize())
	var decoded tokenReview
	if err := json.NewDecoder(limited).Decode(&decoded); err != nil {
		return TokenReviewStatus{}, fmt.Errorf("%w: decode response", ErrTokenReview)
	}
	return decoded.Status, nil
}

type tokenReview struct {
	APIVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	Spec       tokenReviewSpec   `json:"spec,omitempty"`
	Status     TokenReviewStatus `json:"status,omitempty"`
}

type tokenReviewSpec struct {
	Token     string   `json:"token,omitempty"`
	Audiences []string `json:"audiences,omitempty"`
}

func tokenReviewEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("%w: endpoint is required", ErrTokenReview)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%w: endpoint must be an absolute URL", ErrTokenReview)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + tokenReviewPath
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func protocolMaxPayloadSize() int64 {
	return 1 << 20
}
