package broker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dc-tec/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/dc-tec/openbao-attested-unseal/internal/protocol/v1"
)

const (
	// SubjectClaimNamespace is the development evidence claim namespace.
	SubjectClaimNamespace = "dev"
	// SubjectClaimName is the development evidence claim name.
	SubjectClaimName = "subject"
)

// PolicyDecision is a safe policy outcome used by responses, telemetry, and audit.
type PolicyDecision struct {
	State     protocolv1.PolicyDecisionState
	ErrorCode protocolv1.ErrorCode
	PolicyID  string
	Reason    string
}

// Allow returns an allow policy decision.
func Allow(policyID string) PolicyDecision {
	return PolicyDecision{
		State:    protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW,
		PolicyID: policyID,
		Reason:   "allowed by development subject policy",
	}
}

// Deny returns a deny policy decision.
func Deny(policyID string, code protocolv1.ErrorCode, reason string) PolicyDecision {
	return PolicyDecision{
		State:     protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY,
		ErrorCode: code,
		PolicyID:  policyID,
		Reason:    reason,
	}
}

// Proto converts a policy decision to the public protobuf response shape.
func (d PolicyDecision) Proto() *protocolv1.PolicyDecision {
	resp := &protocolv1.PolicyDecision{
		State:    d.State,
		PolicyId: d.PolicyID,
	}
	if d.ErrorCode != protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED || d.Reason != "" {
		resp.Errors = []*protocolv1.BrokerError{
			{
				Code:    d.ErrorCode,
				Message: d.Reason,
			},
		}
	}
	return resp
}

// Allowed returns true when the policy allowed the operation.
func (d PolicyDecision) Allowed() bool {
	return d.State == protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW
}

type policyRequest struct {
	ClusterID   string
	Subject     string
	Operation   protocolv1.Operation
	ChallengeID string
	KeyRef      keyring.KeyRef
}

// PolicyEngine evaluates M2 development-subject policy.
type PolicyEngine struct {
	store     Store
	policyID  string
	clock     func() time.Time
	telemetry *Telemetry
}

// NewPolicyEngine creates the default-deny policy engine.
func NewPolicyEngine(store Store, policyID string, telemetry *Telemetry) *PolicyEngine {
	return &PolicyEngine{
		store:     store,
		policyID:  policyID,
		clock:     time.Now,
		telemetry: telemetry,
	}
}

func (e *PolicyEngine) evaluate(ctx context.Context, req policyRequest) PolicyDecision {
	if req.Subject == "" {
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, "subject evidence is required")
	}
	if _, err := e.store.Subject(ctx, req.ClusterID, req.Subject); err != nil {
		if errors.Is(err, ErrSubjectRevoked) {
			return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "subject is revoked")
		}
		if errors.Is(err, ErrSubjectNotFound) {
			return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "subject is not allowed")
		}
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "subject lookup failed")
	}
	if req.ChallengeID == "" {
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, "challenge is required")
	}
	if err := e.consumeChallenge(
		ctx,
		req,
		req.ChallengeID,
	); err != nil {
		return e.challengeDeny(err)
	}
	version, err := e.store.KeyVersion(ctx, req.KeyRef)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_FOUND, "key version was not found")
		}
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "key lookup failed")
	}
	if req.Operation == protocolv1.Operation_OPERATION_WRAP && version.Status != keyring.StatusActive {
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_USABLE, "wrap requires active key")
	}
	if req.Operation == protocolv1.Operation_OPERATION_UNWRAP {
		switch version.Status {
		case keyring.StatusActive, keyring.StatusDecryptOnly:
		default:
			return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_USABLE, "unwrap requires active or decrypt-only key")
		}
	}
	return Allow(e.policyID)
}

func (e *PolicyEngine) consumeChallenge(
	ctx context.Context,
	req policyRequest,
	challengeID string,
) error {
	if e.telemetry == nil {
		return e.store.ConsumeChallenge(
			ctx,
			challengeID,
			req.ClusterID,
			req.Subject,
			req.Operation,
			e.clock(),
		)
	}
	attrs := safeAttributes(
		req.ClusterID,
		req.KeyRef.KeyID,
		req.KeyRef.Version,
		req.Operation,
		Allow(e.policyID),
		"",
	)
	ctx, span := e.telemetry.start(ctx, "broker.challenge.validate", attrs...)
	defer span.End()
	return e.store.ConsumeChallenge(
		ctx,
		challengeID,
		req.ClusterID,
		req.Subject,
		req.Operation,
		e.clock(),
	)
}

func (e *PolicyEngine) challengeDeny(err error) PolicyDecision {
	switch {
	case errors.Is(err, ErrChallengeExpired):
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "challenge expired")
	case errors.Is(err, ErrChallengeReplayed):
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "challenge was already consumed")
	case errors.Is(err, ErrChallengeNotFound), errors.Is(err, ErrChallengeMismatch):
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "challenge is invalid")
	default:
		return Deny(e.policyID, protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "challenge validation failed")
	}
}

func subjectFromEvidence(evidence *protocolv1.EvidenceEnvelope) string {
	if evidence == nil {
		return ""
	}
	for _, claim := range evidence.GetNormalizedClaims() {
		if claim.GetNamespace() == SubjectClaimNamespace && claim.GetName() == SubjectClaimName {
			return claim.GetValue()
		}
	}
	return ""
}

func keyRefFromProto(ref *protocolv1.KeyRef) (keyring.KeyRef, error) {
	if ref == nil {
		return keyring.KeyRef{}, fmt.Errorf("%w: missing key reference", keyring.ErrInvalidMetadata)
	}
	keyRef := keyring.KeyRef{
		ClusterID: ref.GetClusterId(),
		KeyID:     ref.GetKeyId(),
		Version:   ref.GetVersion(),
	}
	if err := keyRef.Validate(); err != nil {
		return keyring.KeyRef{}, err
	}
	return keyRef, nil
}
