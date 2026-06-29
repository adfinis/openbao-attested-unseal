package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPPodLookupClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/namespaces/openbao/pods/openbao-0" {
			t.Fatalf("path = %q, want pod path", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer reviewer-token" {
			t.Fatalf("authorization = %q, want reviewer bearer token", got)
		}
		_ = json.NewEncoder(w).Encode(podResponse{
			Metadata: podMetadata{Namespace: "openbao", Name: "openbao-0", UID: "pod-uid"},
			Spec:     podSpec{NodeName: "node-a"},
		})
	}))
	defer server.Close()

	pod, err := HTTPPodLookupClient{
		Endpoint:    server.URL,
		BearerToken: "reviewer-token",
	}.LookupPod(context.Background(), "openbao", "openbao-0")
	if err != nil {
		t.Fatalf("LookupPod returned error: %v", err)
	}
	if pod.UID != "pod-uid" || pod.NodeName != "node-a" {
		t.Fatalf("pod = %+v, want UID pod-uid on node-a", pod)
	}
}

func TestHTTPPodLookupClientSanitizesHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "projected-token", http.StatusForbidden)
	}))
	defer server.Close()

	_, err := HTTPPodLookupClient{Endpoint: server.URL}.LookupPod(context.Background(), "openbao", "openbao-0")
	if err == nil {
		t.Fatal("LookupPod returned nil error")
	}
	if strings.Contains(err.Error(), "projected-token") {
		t.Fatal("Pod lookup error leaked token")
	}
}
