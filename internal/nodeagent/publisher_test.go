package nodeagent

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
)

func TestPublisherPublishesFakeLocalNodeEvidence(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	challenge := testNodeEvidenceChallenge(now)
	verified := nodeevidence.Evidence{
		ClusterID:    "prod-eu1",
		NodeName:     "kind-worker",
		NodeUID:      "node-uid",
		Provider:     nodeevidence.ProviderFakeLocal,
		EvidenceHash: "sha256:verified",
		CollectedAt:  now,
		ExpiresAt:    now.Add(5 * time.Minute),
	}
	client := &capturePublisherClient{challenge: challenge, evidence: verified}
	publisher := Publisher{
		Client:   client,
		Provider: FakeLocalProvider{},
		Clock:    func() time.Time { return now },
	}

	evidence, err := publisher.Publish(context.Background(), PublishRequest{
		ClusterID: " prod-eu1 ",
		NodeName:  " kind-worker ",
		NodeUID:   " node-uid ",
		TTL:       5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Publish returned error: %v", err)
	}
	if evidence != verified {
		t.Fatalf("evidence = %#v, want broker record %#v", evidence, verified)
	}
	if client.request != (nodeevidence.ChallengeRequest{
		ClusterID: "prod-eu1",
		NodeName:  "kind-worker",
		NodeUID:   "node-uid",
		Provider:  nodeevidence.ProviderFakeLocal,
	}) {
		t.Fatalf("challenge request = %#v", client.request)
	}
	if client.submission.Provider != nodeevidence.ProviderFakeLocal ||
		client.submission.Format != nodeevidence.FormatFakeLocal ||
		client.submission.ChallengeID != challenge.ID ||
		client.submission.RequestedTTL != 5*time.Minute ||
		len(client.submission.Payload) == 0 {
		t.Fatalf("submission = %#v, want challenge-bound fake-local payload", client.submission)
	}

	repeated, err := (FakeLocalProvider{}).CollectNodeEvidence(
		context.Background(),
		PublishRequest{
			ClusterID: "prod-eu1",
			NodeName:  "kind-worker",
			NodeUID:   "node-uid",
			TTL:       time.Minute,
		},
		challenge,
	)
	if err != nil {
		t.Fatalf("CollectNodeEvidence returned error: %v", err)
	}
	if !bytes.Equal(repeated.Payload, client.submission.Payload) {
		t.Fatalf("repeated fake-local payload differs from submitted payload")
	}
}

func TestPublisherRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	client := &capturePublisherClient{challenge: testNodeEvidenceChallenge(now)}
	tests := map[string]struct {
		publisher Publisher
		request   PublishRequest
		want      error
	}{
		"missing cluster": {
			publisher: Publisher{Client: client, Provider: FakeLocalProvider{}, Clock: func() time.Time { return now }},
			request:   PublishRequest{NodeName: "node-a", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"missing node": {
			publisher: Publisher{Client: client, Provider: FakeLocalProvider{}, Clock: func() time.Time { return now }},
			request:   PublishRequest{ClusterID: "prod-eu1", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"missing ttl": {
			publisher: Publisher{Client: client, Provider: FakeLocalProvider{}, Clock: func() time.Time { return now }},
			request:   PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a"},
			want:      ErrInvalidPublishRequest,
		},
		"missing client": {
			publisher: Publisher{Provider: FakeLocalProvider{}},
			request:   PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"missing provider": {
			publisher: Publisher{Client: client},
			request:   PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"invalid provider evidence": {
			publisher: Publisher{
				Client:   client,
				Provider: staticProvider{id: nodeevidence.ProviderFakeLocal},
				Clock:    func() time.Time { return now },
			},
			request: PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute},
			want:    ErrInvalidProviderEvidence,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := test.publisher.Publish(context.Background(), test.request)
			if !errors.Is(err, test.want) {
				t.Fatalf("Publish error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPublisherReturnsChallengeProviderAndSubmitErrors(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0).UTC()
	challengeErr := errors.New("challenge failed")
	providerErr := errors.New("provider failed")
	submitErr := errors.New("submit failed")
	request := PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute}

	_, err := (Publisher{
		Client:   &capturePublisherClient{challengeErr: challengeErr},
		Provider: FakeLocalProvider{},
		Clock:    func() time.Time { return now },
	}).Publish(context.Background(), request)
	if !errors.Is(err, challengeErr) {
		t.Fatalf("challenge Publish error = %v, want %v", err, challengeErr)
	}

	_, err = (Publisher{
		Client: &capturePublisherClient{challenge: testNodeEvidenceChallenge(now)},
		Provider: staticProvider{
			id:  nodeevidence.ProviderFakeLocal,
			err: providerErr,
		},
		Clock: func() time.Time { return now },
	}).Publish(context.Background(), request)
	if !errors.Is(err, providerErr) {
		t.Fatalf("provider Publish error = %v, want %v", err, providerErr)
	}

	_, err = (Publisher{
		Client: &capturePublisherClient{
			challenge: testNodeEvidenceChallenge(now),
			submitErr: submitErr,
		},
		Provider: FakeLocalProvider{},
		Clock:    func() time.Time { return now },
	}).Publish(context.Background(), request)
	if !errors.Is(err, submitErr) {
		t.Fatalf("submit Publish error = %v, want %v", err, submitErr)
	}
}

type capturePublisherClient struct {
	request      nodeevidence.ChallengeRequest
	challenge    nodeevidence.Challenge
	challengeErr error
	submission   nodeevidence.Submission
	evidence     nodeevidence.Evidence
	submitErr    error
}

func (c *capturePublisherClient) RequestNodeEvidenceChallenge(
	_ context.Context,
	request nodeevidence.ChallengeRequest,
) (nodeevidence.Challenge, error) {
	c.request = request
	return c.challenge, c.challengeErr
}

func (c *capturePublisherClient) SubmitNodeEvidence(
	_ context.Context,
	submission nodeevidence.Submission,
) (nodeevidence.Evidence, error) {
	c.submission = submission
	return c.evidence, c.submitErr
}

type staticProvider struct {
	id       string
	evidence ProviderEvidence
	err      error
}

func (p staticProvider) ProviderID() string {
	return p.id
}

func (p staticProvider) CollectNodeEvidence(
	context.Context,
	PublishRequest,
	nodeevidence.Challenge,
) (ProviderEvidence, error) {
	return p.evidence, p.err
}

func testNodeEvidenceChallenge(now time.Time) nodeevidence.Challenge {
	return nodeevidence.Challenge{
		ID:        "node_chal_test",
		Nonce:     bytes.Repeat([]byte{0x42}, 32),
		ExpiresAt: now.Add(time.Minute),
	}
}
