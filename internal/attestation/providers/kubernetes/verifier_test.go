package kubernetes

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

func TestVerifierAcceptsTokenReviewServiceAccount(t *testing.T) {
	reviewer := &fakeReviewer{
		status: TokenReviewStatus{
			Authenticated: true,
			User: UserInfo{
				Username: "system:serviceaccount:openbao:openbao",
				UID:      "sa-uid",
				Groups:   []string{"system:serviceaccounts"},
				Extra: map[string][]string{
					extraPodName:  {"openbao-0"},
					extraPodUID:   {"pod-uid"},
					extraNodeName: {"node-a"},
					extraNodeUID:  {"node-uid"},
				},
			},
			Audiences: []string{"bao-unseald"},
		},
	}
	envelope, err := NewEvidenceEnvelope("chal_test", "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	verified, claims, err := Verifier{
		Reviewer: reviewer,
		Config: VerifierConfig{
			Audience:          "bao-unseald",
			Namespace:         "openbao",
			ServiceAccount:    "openbao",
			RequirePodBinding: true,
		},
	}.Verify(context.Background(), envelope)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if reviewer.request.Token != "projected-token" {
		t.Fatalf("reviewed token = %q, want projected-token", reviewer.request.Token)
	}
	if !slices.Equal(reviewer.request.Audiences, []string{"bao-unseald"}) {
		t.Fatalf("audiences = %v, want [bao-unseald]", reviewer.request.Audiences)
	}
	if claims.Subject != "openbao.openbao" {
		t.Fatalf("subject = %q, want openbao.openbao", claims.Subject)
	}
	if claims.PodUID != "pod-uid" || claims.NodeName != "node-a" {
		t.Fatalf("pod/node claims = %q/%q, want pod-uid/node-a", claims.PodUID, claims.NodeName)
	}
	if got := claimValue(verified.NormalizedClaims, "dev", "subject"); got != "openbao.openbao" {
		t.Fatalf("normalized subject = %q, want openbao.openbao", got)
	}
	if got := claimValue(verified.NormalizedClaims, ClaimNamespace, "node_name"); got != "node-a" {
		t.Fatalf("normalized node_name = %q, want node-a", got)
	}
}

func TestVerifierRejectsWrongAudience(t *testing.T) {
	envelope, err := NewEvidenceEnvelope("chal_test", "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	_, _, err = Verifier{
		Reviewer: &fakeReviewer{
			status: TokenReviewStatus{
				Authenticated: true,
				User:          UserInfo{Username: "system:serviceaccount:openbao:openbao"},
				Audiences:     []string{"other-audience"},
			},
		},
		Config: VerifierConfig{Audience: "bao-unseald"},
	}.Verify(context.Background(), envelope)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("Verify error = %v, want ErrInvalidEvidence", err)
	}
	if strings.Contains(err.Error(), "projected-token") {
		t.Fatal("verification error leaked token")
	}
}

func TestVerifierRejectsUnauthenticatedToken(t *testing.T) {
	envelope, err := NewEvidenceEnvelope("chal_test", "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	_, _, err = Verifier{
		Reviewer: &fakeReviewer{status: TokenReviewStatus{Authenticated: false}},
	}.Verify(context.Background(), envelope)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Verify error = %v, want ErrUnauthenticated", err)
	}
}

func TestVerifierRejectsNonServiceAccountUsername(t *testing.T) {
	envelope, err := NewEvidenceEnvelope("chal_test", "projected-token")
	if err != nil {
		t.Fatalf("NewEvidenceEnvelope returned error: %v", err)
	}
	_, _, err = Verifier{
		Reviewer: &fakeReviewer{
			status: TokenReviewStatus{
				Authenticated: true,
				User:          UserInfo{Username: "alice"},
			},
		},
	}.Verify(context.Background(), envelope)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("Verify error = %v, want ErrInvalidEvidence", err)
	}
}

type fakeReviewer struct {
	request TokenReviewRequest
	status  TokenReviewStatus
	err     error
}

func (r *fakeReviewer) ReviewToken(_ context.Context, request TokenReviewRequest) (TokenReviewStatus, error) {
	r.request = request
	if r.err != nil {
		return TokenReviewStatus{}, r.err
	}
	return r.status, nil
}

func claimValue(claims []*protocolv1.Claim, namespace string, name string) string {
	for _, claim := range claims {
		if claim.GetNamespace() == namespace && claim.GetName() == name {
			return claim.GetValue()
		}
	}
	return ""
}
