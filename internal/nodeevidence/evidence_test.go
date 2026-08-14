package nodeevidence

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestUntrustedEvidenceContractsNormalizeAndClone(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)
	nonce := []byte("broker-nonce")
	payload := []byte("raw-evidence")

	request, err := NormalizeChallengeRequest(ChallengeRequest{
		ClusterID: " cluster ",
		NodeName:  " node-1 ",
		NodeUID:   " uid-1 ",
		Provider:  " provider ",
	})
	if err != nil {
		t.Fatalf("NormalizeChallengeRequest() error = %v", err)
	}
	if request.ClusterID != "cluster" || request.NodeName != "node-1" ||
		request.NodeUID != "uid-1" || request.Provider != "provider" {
		t.Fatalf("NormalizeChallengeRequest() = %#v", request)
	}

	challenge, err := NormalizeChallenge(Challenge{
		ID:        " challenge ",
		Nonce:     nonce,
		ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("NormalizeChallenge() error = %v", err)
	}
	nonce[0] = 'X'
	if challenge.ID != "challenge" || bytes.Equal(challenge.Nonce, nonce) {
		t.Fatalf("NormalizeChallenge() did not trim and clone: %#v", challenge)
	}

	submission, err := NormalizeSubmission(Submission{
		ClusterID:    " cluster ",
		NodeName:     " node-1 ",
		NodeUID:      " uid-1 ",
		Provider:     " provider ",
		Format:       " format ",
		Payload:      payload,
		ChallengeID:  " challenge ",
		RequestedTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("NormalizeSubmission() error = %v", err)
	}
	payload[0] = 'X'
	if submission.Format != "format" || submission.ChallengeID != "challenge" ||
		bytes.Equal(submission.Payload, payload) {
		t.Fatalf("NormalizeSubmission() did not trim and clone: %#v", submission)
	}
}

func TestFakeLocalPayloadIsChallengeBound(t *testing.T) {
	t.Parallel()
	request := ChallengeRequest{
		ClusterID: "cluster",
		NodeName:  "node-1",
		Provider:  ProviderFakeLocal,
	}
	first, err := FakeLocalPayload(request, Challenge{ID: "challenge", Nonce: []byte("nonce-a")})
	if err != nil {
		t.Fatalf("FakeLocalPayload() error = %v", err)
	}
	second, err := FakeLocalPayload(request, Challenge{ID: "challenge", Nonce: []byte("nonce-b")})
	if err != nil {
		t.Fatalf("FakeLocalPayload() second error = %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("FakeLocalPayload() did not bind the broker nonce")
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		input   Evidence
		wantErr error
	}{
		{
			name: "valid",
			input: Evidence{
				ClusterID:    " cluster ",
				NodeName:     " node-1 ",
				NodeUID:      " uid-1 ",
				Provider:     " provider ",
				EvidenceHash: " sha256:abc ",
				CollectedAt:  now,
				ExpiresAt:    now.Add(time.Minute),
			},
		},
		{
			name: "missing identity",
			input: Evidence{
				CollectedAt: now,
				ExpiresAt:   now.Add(time.Minute),
			},
			wantErr: ErrInvalid,
		},
		{
			name: "missing timestamps",
			input: Evidence{
				ClusterID: "cluster",
				NodeName:  "node-1",
			},
			wantErr: ErrInvalid,
		},
		{
			name: "non-increasing expiry",
			input: Evidence{
				ClusterID:   "cluster",
				NodeName:    "node-1",
				CollectedAt: now,
				ExpiresAt:   now,
			},
			wantErr: ErrInvalid,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := Normalize(test.input)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("Normalize() error = %v, want %v", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if got.ClusterID != "cluster" || got.NodeName != "node-1" || got.NodeUID != "uid-1" {
				t.Fatalf("Normalize() identity = %#v", got)
			}
			if got.Provider != "provider" || got.EvidenceHash != "sha256:abc" {
				t.Fatalf("Normalize() provider metadata = %#v", got)
			}
		})
	}
}

func TestMemoryRepositoryLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Date(2026, time.August, 11, 10, 0, 0, 0, time.UTC)
	record := Evidence{
		ClusterID:    "cluster",
		NodeName:     "node-1",
		NodeUID:      "uid-1",
		Provider:     ProviderTPM2Quote,
		EvidenceHash: "sha256:abc",
		CollectedAt:  now,
		ExpiresAt:    now.Add(time.Minute),
	}
	repository := NewMemoryRepository()

	if err := repository.PutNodeEvidence(ctx, record); err != nil {
		t.Fatalf("PutNodeEvidence() error = %v", err)
	}
	fresh, err := repository.FreshNodeEvidence(ctx, record.ClusterID, record.NodeName, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("FreshNodeEvidence() error = %v", err)
	}
	if fresh != record {
		t.Fatalf("FreshNodeEvidence() = %#v, want %#v", fresh, record)
	}
	_, err = repository.FreshNodeEvidence(
		ctx,
		record.ClusterID,
		record.NodeName,
		record.ExpiresAt,
	)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("expired FreshNodeEvidence() error = %v, want %v", err, ErrStale)
	}
	stored, err := repository.NodeEvidence(ctx, record.ClusterID, record.NodeName)
	if err != nil || stored != record {
		t.Fatalf("NodeEvidence() = %#v, %v, want %#v", stored, err, record)
	}
	records, err := repository.ListNodeEvidence(ctx, record.ClusterID, "")
	if err != nil || len(records) != 1 || records[0] != record {
		t.Fatalf("ListNodeEvidence() = %#v, %v", records, err)
	}
	removed, err := repository.PruneNodeEvidence(ctx, record.ClusterID, record.ExpiresAt.Add(time.Nanosecond))
	if err != nil || removed != 1 {
		t.Fatalf("PruneNodeEvidence() = %d, %v, want 1, nil", removed, err)
	}
	if _, err := repository.NodeEvidence(ctx, record.ClusterID, record.NodeName); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned NodeEvidence() error = %v, want %v", err, ErrNotFound)
	}
}
