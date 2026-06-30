package brokeradmin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// ErrPublishNodeEvidence indicates a broker admin node evidence publish RPC failed.
var ErrPublishNodeEvidence = errors.New("publish node evidence")

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

// NodeEvidenceWriter publishes node evidence through the broker admin API.
type NodeEvidenceWriter struct {
	Client   protocolv1.AdminServiceClient
	Evidence *protocolv1.NodeEvidenceRecord
	Decision *protocolv1.PolicyDecision
}

// PutNodeEvidence publishes one node evidence record.
func (w *NodeEvidenceWriter) PutNodeEvidence(
	ctx context.Context,
	evidence broker.NodeEvidence,
) error {
	if w == nil || w.Client == nil {
		return fmt.Errorf("%w: admin client is required", ErrPublishNodeEvidence)
	}
	response, err := w.Client.PublishNodeEvidence(ctx, &protocolv1.NodeEvidencePublishRequest{
		Evidence: &protocolv1.NodeEvidenceRecord{
			ClusterId:            evidence.ClusterID,
			NodeName:             evidence.NodeName,
			NodeUid:              evidence.NodeUID,
			ProviderId:           evidence.Provider,
			EvidenceHash:         evidence.EvidenceHash,
			CollectedUnixSeconds: evidence.CollectedAt.Unix(),
			ExpiresUnixSeconds:   evidence.ExpiresAt.Unix(),
		},
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPublishNodeEvidence, err)
	}
	w.Evidence = response.GetEvidence()
	w.Decision = response.GetDecision()
	if err := RequireAllowDecision(response.GetDecision(), "publish node evidence"); err != nil {
		return err
	}
	return nil
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
