package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPTokenReviewClient(t *testing.T) {
	var reviewed tokenReview
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tokenReviewPath {
			t.Fatalf("path = %q, want %q", r.URL.Path, tokenReviewPath)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer reviewer-token" {
			t.Fatalf("authorization = %q, want reviewer bearer token", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&reviewed); err != nil {
			t.Fatalf("Decode request returned error: %v", err)
		}
		_ = json.NewEncoder(w).Encode(tokenReview{
			Status: TokenReviewStatus{
				Authenticated: true,
				User:          UserInfo{Username: "system:serviceaccount:openbao:openbao"},
				Audiences:     []string{"bao-unseald"},
			},
		})
	}))
	defer server.Close()

	status, err := HTTPTokenReviewClient{
		Endpoint:    server.URL,
		BearerToken: "reviewer-token",
	}.ReviewToken(context.Background(), TokenReviewRequest{
		Token:     "projected-token",
		Audiences: []string{"bao-unseald"},
	})
	if err != nil {
		t.Fatalf("ReviewToken returned error: %v", err)
	}
	if reviewed.Spec.Token != "projected-token" {
		t.Fatalf("reviewed token = %q, want projected-token", reviewed.Spec.Token)
	}
	if len(reviewed.Spec.Audiences) != 1 || reviewed.Spec.Audiences[0] != "bao-unseald" {
		t.Fatalf("reviewed audiences = %v, want [bao-unseald]", reviewed.Spec.Audiences)
	}
	if !status.Authenticated {
		t.Fatal("authenticated = false, want true")
	}
	if status.User.Username != "system:serviceaccount:openbao:openbao" {
		t.Fatalf("username = %q", status.User.Username)
	}
}

func TestHTTPTokenReviewClientSanitizesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "projected-token", http.StatusForbidden)
	}))
	defer server.Close()

	_, err := HTTPTokenReviewClient{Endpoint: server.URL}.ReviewToken(
		context.Background(),
		TokenReviewRequest{Token: "projected-token"},
	)
	if err == nil {
		t.Fatal("ReviewToken returned nil error")
	}
	if strings.Contains(err.Error(), "projected-token") {
		t.Fatal("TokenReview error leaked token")
	}
}
