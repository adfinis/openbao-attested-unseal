package brokeradmin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// ErrPublishNodeEvidence indicates a broker admin node evidence publish RPC failed.
var ErrPublishNodeEvidence = errors.New("publish node evidence")

// ErrChallengeNodeEvidence indicates a broker admin challenge RPC failed.
var ErrChallengeNodeEvidence = errors.New("challenge node evidence")

// DecisionDeniedError indicates a broker admin operation returned a deny decision.
type DecisionDeniedError struct {
	Operation string
	Messages  []string
}

// Error returns the broker denial message.
func (e DecisionDeniedError) Error() string {
	operation := strings.TrimSpace(e.Operation)
	if operation == "" {
		operation = "operation"
	}
	if len(e.Messages) == 0 {
		return fmt.Sprintf("broker denied %s", operation)
	}
	return fmt.Sprintf("broker denied %s: %s", operation, strings.Join(e.Messages, "; "))
}

// NodeEvidenceClient completes the broker challenge and submission protocol.
type NodeEvidenceClient struct {
	Client   protocolv1.AdminServiceClient
	Evidence *protocolv1.NodeEvidenceRecord
	Decision *protocolv1.PolicyDecision
}

// RequestNodeEvidenceChallenge requests one single-use broker challenge.
func (w *NodeEvidenceClient) RequestNodeEvidenceChallenge(
	ctx context.Context,
	request nodeevidence.ChallengeRequest,
) (nodeevidence.Challenge, error) {
	if w == nil || w.Client == nil {
		return nodeevidence.Challenge{}, fmt.Errorf("%w: admin client is required", ErrChallengeNodeEvidence)
	}
	request, err := nodeevidence.NormalizeChallengeRequest(request)
	if err != nil {
		return nodeevidence.Challenge{}, err
	}
	response, err := w.Client.ChallengeNodeEvidence(ctx, &protocolv1.NodeEvidenceChallengeRequest{
		ClusterId:  request.ClusterID,
		NodeName:   request.NodeName,
		NodeUid:    request.NodeUID,
		ProviderId: request.Provider,
	})
	if err != nil {
		return nodeevidence.Challenge{}, fmt.Errorf("%w: %w", ErrChallengeNodeEvidence, err)
	}
	w.Decision = response.GetDecision()
	if err := RequireAllowDecision(response.GetDecision(), "challenge node evidence"); err != nil {
		return nodeevidence.Challenge{}, err
	}
	return nodeevidence.NormalizeChallenge(nodeevidence.Challenge{
		ID:        response.GetChallengeId(),
		Nonce:     response.GetNonce(),
		ExpiresAt: time.Unix(response.GetExpiresUnixSeconds(), 0).UTC(),
	})
}

// SubmitNodeEvidence submits untrusted evidence and returns the broker-verified record.
func (w *NodeEvidenceClient) SubmitNodeEvidence(
	ctx context.Context,
	submission nodeevidence.Submission,
) (nodeevidence.Evidence, error) {
	if w == nil || w.Client == nil {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: admin client is required", ErrPublishNodeEvidence)
	}
	submission, err := nodeevidence.NormalizeSubmission(submission)
	if err != nil {
		return nodeevidence.Evidence{}, err
	}
	response, err := w.Client.PublishNodeEvidence(ctx, &protocolv1.NodeEvidencePublishRequest{
		Submission: &protocolv1.NodeEvidenceSubmission{
			ClusterId:           submission.ClusterID,
			NodeName:            submission.NodeName,
			NodeUid:             submission.NodeUID,
			ProviderId:          submission.Provider,
			Format:              submission.Format,
			Payload:             submission.Payload,
			ChallengeId:         submission.ChallengeID,
			RequestedTtlSeconds: durationSecondsCeiling(submission.RequestedTTL),
		},
	})
	if err != nil {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: %w", ErrPublishNodeEvidence, err)
	}
	w.Evidence = response.GetEvidence()
	w.Decision = response.GetDecision()
	if err := RequireAllowDecision(response.GetDecision(), "publish node evidence"); err != nil {
		return nodeevidence.Evidence{}, err
	}
	return nodeEvidenceFromProto(response.GetEvidence())
}

func nodeEvidenceFromProto(record *protocolv1.NodeEvidenceRecord) (nodeevidence.Evidence, error) {
	if record == nil {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: response record is required", ErrPublishNodeEvidence)
	}
	return nodeevidence.Normalize(nodeevidence.Evidence{
		ClusterID:    record.GetClusterId(),
		NodeName:     record.GetNodeName(),
		NodeUID:      record.GetNodeUid(),
		Provider:     record.GetProviderId(),
		EvidenceHash: record.GetEvidenceHash(),
		CollectedAt:  time.Unix(record.GetCollectedUnixSeconds(), 0).UTC(),
		ExpiresAt:    time.Unix(record.GetExpiresUnixSeconds(), 0).UTC(),
	})
}

func durationSecondsCeiling(duration time.Duration) int64 {
	seconds := duration / time.Second
	if duration%time.Second != 0 {
		seconds++
	}
	return int64(seconds)
}

// RequireAllowDecision returns a denial error unless the policy decision is allow.
func RequireAllowDecision(decision *protocolv1.PolicyDecision, operation string) error {
	if decision.GetState() == protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		return nil
	}
	return DecisionDeniedError{
		Operation: operation,
		Messages:  DecisionMessages(decision),
	}
}

// DecisionMessages extracts human-readable broker decision messages.
func DecisionMessages(decision *protocolv1.PolicyDecision) []string {
	messages := make([]string, 0, len(decision.GetErrors()))
	for _, brokerErr := range decision.GetErrors() {
		if brokerErr.GetMessage() != "" {
			messages = append(messages, brokerErr.GetMessage())
		}
	}
	return messages
}

// DecisionMessage returns the first useful denial message or fallback.
func DecisionMessage(decision *protocolv1.PolicyDecision, fallback string) string {
	messages := DecisionMessages(decision)
	if len(messages) == 0 {
		return fallback
	}
	return strings.Join(messages, "; ")
}

// UnixSecondsOutput renders a protobuf unix timestamp as RFC3339.
func UnixSecondsOutput(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}

// NodeEvidenceStatusOutput renders a node evidence status enum for operator output.
func NodeEvidenceStatusOutput(status protocolv1.NodeEvidenceStatus) string {
	switch status {
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_FRESH:
		return "fresh"
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_STALE:
		return "stale"
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_MISSING:
		return "missing"
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_INVALID:
		return "invalid"
	default:
		return "unspecified"
	}
}

// PolicyDecisionOutput renders a policy decision enum for operator output.
func PolicyDecisionOutput(state protocolv1.PolicyDecisionState) string {
	switch state {
	case protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW:
		return "allow"
	case protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY:
		return "deny"
	default:
		return "unspecified"
	}
}
