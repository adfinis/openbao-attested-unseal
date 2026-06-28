package enrollment

import (
	"errors"
	"testing"
	"time"
)

func TestGrantSignatureValidation(t *testing.T) {
	now := time.Now()
	request := testRequest(t, now)
	_, privateKey, err := GenerateIssuer(nil)
	if err != nil {
		t.Fatalf("GenerateIssuer returned error: %v", err)
	}
	grant, err := IssueGrant(request, privateKey, GrantOptions{
		GrantID:   "grant_test",
		KeyID:     "root",
		PolicyID:  "development",
		ExpiresAt: now.Add(time.Hour),
		OneTime:   true,
	}, now)
	if err != nil {
		t.Fatalf("IssueGrant returned error: %v", err)
	}
	if err := grant.Verify(now); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
}

func TestGrantSignatureRejectsTampering(t *testing.T) {
	now := time.Now()
	request := testRequest(t, now)
	_, privateKey, err := GenerateIssuer(nil)
	if err != nil {
		t.Fatalf("GenerateIssuer returned error: %v", err)
	}
	grant, err := IssueGrant(request, privateKey, GrantOptions{
		GrantID:   "grant_test",
		KeyID:     "root",
		PolicyID:  "development",
		ExpiresAt: now.Add(time.Hour),
		OneTime:   true,
	}, now)
	if err != nil {
		t.Fatalf("IssueGrant returned error: %v", err)
	}
	grant.SubjectID = "node-b"
	if err := grant.Verify(now); !errors.Is(err, ErrSignature) {
		t.Fatalf("Verify error = %v, want ErrSignature", err)
	}
}

func TestExpiredEnrollmentGrantRejected(t *testing.T) {
	now := time.Now()
	request := testRequest(t, now)
	_, privateKey, err := GenerateIssuer(nil)
	if err != nil {
		t.Fatalf("GenerateIssuer returned error: %v", err)
	}
	grant, err := IssueGrant(request, privateKey, GrantOptions{
		GrantID:   "grant_test",
		KeyID:     "root",
		PolicyID:  "development",
		ExpiresAt: now.Add(time.Minute),
		OneTime:   true,
	}, now)
	if err != nil {
		t.Fatalf("IssueGrant returned error: %v", err)
	}
	if err := grant.Verify(now.Add(2 * time.Minute)); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify error = %v, want ErrExpired", err)
	}
}

func testRequest(t *testing.T, now time.Time) Request {
	t.Helper()
	request, err := NewRequest(RequestOptions{
		RequestID:         "req_test",
		ClusterID:         "prod-eu1",
		SubjectID:         "node-a",
		AllowedOperations: []string{"wrap", "unwrap"},
		EvidenceFormat:    "development-subject",
		EvidencePayload:   []byte("node-a"),
		PublicIdentity:    "identity-node-a",
		Nonce:             "nonce-test",
		ExpiresAt:         now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewRequest returned error: %v", err)
	}
	return request
}
