package nodeagent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
)

func TestPublisherPublishesFakeLocalNodeEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	writer := &captureNodeEvidenceWriter{}
	publisher := Publisher{
		Writer:   writer,
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
	if evidence.ClusterID != "prod-eu1" ||
		evidence.NodeName != "kind-worker" ||
		evidence.NodeUID != "node-uid" ||
		evidence.Provider != broker.NodeEvidenceProviderFakeLocal ||
		evidence.EvidenceHash == "" ||
		!evidence.CollectedAt.Equal(now) ||
		!evidence.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("evidence = %#v, want normalized fake-local record", evidence)
	}
	if writer.evidence != evidence {
		t.Fatalf("writer evidence = %#v, want %#v", writer.evidence, evidence)
	}

	repeated, err := (FakeLocalProvider{}).CollectNodeEvidence(context.Background(), PublishRequest{
		ClusterID: "prod-eu1",
		NodeName:  "kind-worker",
		NodeUID:   "node-uid",
		TTL:       time.Minute,
	})
	if err != nil {
		t.Fatalf("CollectNodeEvidence returned error: %v", err)
	}
	if repeated.EvidenceHash != evidence.EvidenceHash {
		t.Fatalf("repeated fake-local hash = %q, want %q", repeated.EvidenceHash, evidence.EvidenceHash)
	}
}

func TestPublisherRejectsInvalidInput(t *testing.T) {
	tests := map[string]struct {
		publisher Publisher
		request   PublishRequest
		want      error
	}{
		"missing cluster": {
			publisher: Publisher{Writer: &captureNodeEvidenceWriter{}, Provider: FakeLocalProvider{}},
			request:   PublishRequest{NodeName: "node-a", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"missing node": {
			publisher: Publisher{Writer: &captureNodeEvidenceWriter{}, Provider: FakeLocalProvider{}},
			request:   PublishRequest{ClusterID: "prod-eu1", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"missing ttl": {
			publisher: Publisher{Writer: &captureNodeEvidenceWriter{}, Provider: FakeLocalProvider{}},
			request:   PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a"},
			want:      ErrInvalidPublishRequest,
		},
		"missing writer": {
			publisher: Publisher{Provider: FakeLocalProvider{}},
			request:   PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"missing provider": {
			publisher: Publisher{Writer: &captureNodeEvidenceWriter{}},
			request:   PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute},
			want:      ErrInvalidPublishRequest,
		},
		"invalid provider evidence": {
			publisher: Publisher{
				Writer:   &captureNodeEvidenceWriter{},
				Provider: staticProvider{},
			},
			request: PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute},
			want:    ErrInvalidProviderEvidence,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tc.publisher.Publish(context.Background(), tc.request)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Publish error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPublisherReturnsProviderAndWriterErrors(t *testing.T) {
	providerErr := errors.New("provider failed")
	writerErr := errors.New("writer failed")
	request := PublishRequest{ClusterID: "prod-eu1", NodeName: "node-a", TTL: time.Minute}

	_, err := (Publisher{
		Writer:   &captureNodeEvidenceWriter{},
		Provider: staticProvider{err: providerErr},
	}).Publish(context.Background(), request)
	if !errors.Is(err, providerErr) {
		t.Fatalf("provider Publish error = %v, want %v", err, providerErr)
	}

	_, err = (Publisher{
		Writer: &captureNodeEvidenceWriter{err: writerErr},
		Provider: staticProvider{evidence: ProviderEvidence{
			ProviderID:   broker.NodeEvidenceProviderFakeLocal,
			EvidenceHash: "hash",
		}},
	}).Publish(context.Background(), request)
	if !errors.Is(err, writerErr) {
		t.Fatalf("writer Publish error = %v, want %v", err, writerErr)
	}
}

type captureNodeEvidenceWriter struct {
	evidence broker.NodeEvidence
	err      error
}

func (w *captureNodeEvidenceWriter) PutNodeEvidence(_ context.Context, evidence broker.NodeEvidence) error {
	w.evidence = evidence
	return w.err
}

type staticProvider struct {
	evidence ProviderEvidence
	err      error
}

func (p staticProvider) CollectNodeEvidence(context.Context, PublishRequest) (ProviderEvidence, error) {
	return p.evidence, p.err
}
