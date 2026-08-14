package broker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// MemoryChallengeStore is a process-local challenge store for tests and development helpers.
type MemoryChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]memoryChallenge
}

type memoryChallenge struct {
	challenge Challenge
	consumed  bool
}

// NewMemoryChallengeStore creates an empty process-local challenge store.
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{challenges: make(map[string]memoryChallenge)}
}

// CreateChallenge stores one challenge.
func (s *MemoryChallengeStore) CreateChallenge(_ context.Context, challenge Challenge) error {
	if s == nil {
		return fmt.Errorf("challenge store is nil")
	}
	if strings.TrimSpace(challenge.ID) == "" || len(challenge.Nonce) == 0 {
		return fmt.Errorf("challenge id and nonce are required")
	}
	challenge.Nonce = slices.Clone(challenge.Nonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.challenges[challenge.ID]; exists {
		return fmt.Errorf("challenge %q already exists", challenge.ID)
	}
	s.challenges[challenge.ID] = memoryChallenge{challenge: challenge}
	return nil
}

// ChallengeNonce returns a validated challenge nonce without consuming it.
func (s *MemoryChallengeStore) ChallengeNonce(
	_ context.Context,
	challengeID string,
	clusterID string,
	subject string,
	operation protocolv1.Operation,
	now time.Time,
) ([]byte, error) {
	if s == nil {
		return nil, ErrChallengeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.validChallenge(challengeID, clusterID, subject, operation, now)
	if err != nil {
		return nil, err
	}
	return slices.Clone(stored.challenge.Nonce), nil
}

// ConsumeChallenge validates and consumes one challenge exactly once.
func (s *MemoryChallengeStore) ConsumeChallenge(
	_ context.Context,
	challengeID string,
	clusterID string,
	subject string,
	operation protocolv1.Operation,
	now time.Time,
) error {
	if s == nil {
		return ErrChallengeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.validChallenge(challengeID, clusterID, subject, operation, now)
	if err != nil {
		return err
	}
	stored.consumed = true
	s.challenges[challengeID] = stored
	return nil
}

func (s *MemoryChallengeStore) validChallenge(
	challengeID string,
	clusterID string,
	subject string,
	operation protocolv1.Operation,
	now time.Time,
) (memoryChallenge, error) {
	if s == nil {
		return memoryChallenge{}, ErrChallengeNotFound
	}
	stored, ok := s.challenges[challengeID]
	if !ok {
		return memoryChallenge{}, ErrChallengeNotFound
	}
	challenge := stored.challenge
	if challenge.ClusterID != clusterID || challenge.Subject != subject || challenge.Operation != operation {
		return memoryChallenge{}, ErrChallengeMismatch
	}
	if stored.consumed {
		return memoryChallenge{}, ErrChallengeReplayed
	}
	if !now.Before(challenge.ExpiresAt) {
		return memoryChallenge{}, ErrChallengeExpired
	}
	return stored, nil
}
