package broker

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

const maxNodeEvidencePayloadSize = 1024 * 1024

// ErrNodeEvidenceVerification marks an untrusted submission that failed broker verification.
var ErrNodeEvidenceVerification = errors.New("node evidence verification failed")

func verifyNodeEvidenceSubmission(
	submission nodeevidence.Submission,
	nonce []byte,
	enrollment nodeevidence.Enrollment,
) (nodeevidence.Evidence, error) {
	if len(submission.Payload) > maxNodeEvidencePayloadSize {
		return nodeevidence.Evidence{}, fmt.Errorf("%w: payload exceeds maximum size", ErrNodeEvidenceVerification)
	}
	switch submission.Provider {
	case nodeevidence.ProviderFakeLocal:
		if err := verifyFakeLocalSubmission(submission, nonce); err != nil {
			return nodeevidence.Evidence{}, err
		}
	case nodeevidence.ProviderTPM2Quote:
		if err := verifyTPMNodeEvidenceSubmission(submission, nonce, enrollment); err != nil {
			return nodeevidence.Evidence{}, err
		}
	default:
		return nodeevidence.Evidence{}, fmt.Errorf(
			"%w: unsupported provider %q",
			ErrNodeEvidenceVerification,
			submission.Provider,
		)
	}
	return nodeevidence.Evidence{
		ClusterID:    submission.ClusterID,
		NodeName:     submission.NodeName,
		NodeUID:      submission.NodeUID,
		Provider:     submission.Provider,
		EvidenceHash: nodeEvidencePayloadHash(submission.Payload),
	}, nil
}

func verifyFakeLocalSubmission(submission nodeevidence.Submission, nonce []byte) error {
	if submission.Format != nodeevidence.FormatFakeLocal {
		return fmt.Errorf("%w: unsupported fake-local format", ErrNodeEvidenceVerification)
	}
	expected, err := nodeevidence.FakeLocalPayload(
		nodeevidence.ChallengeRequest{
			ClusterID: submission.ClusterID,
			NodeName:  submission.NodeName,
			NodeUID:   submission.NodeUID,
			Provider:  submission.Provider,
		},
		nodeevidence.Challenge{ID: submission.ChallengeID, Nonce: nonce},
	)
	if err != nil {
		return fmt.Errorf("%w: invalid fake-local evidence", ErrNodeEvidenceVerification)
	}
	if subtle.ConstantTimeCompare(expected, submission.Payload) != 1 {
		return fmt.Errorf("%w: fake-local challenge mismatch", ErrNodeEvidenceVerification)
	}
	return nil
}

func verifyTPMNodeEvidenceSubmission(
	submission nodeevidence.Submission,
	nonce []byte,
	enrollment nodeevidence.Enrollment,
) error {
	if submission.Format != tpmlocal.EvidenceFormat {
		return fmt.Errorf("%w: unsupported TPM evidence format", ErrNodeEvidenceVerification)
	}
	if !enrollment.Active() || enrollment.NodeName != submission.NodeName ||
		enrollment.ClusterID != submission.ClusterID {
		return fmt.Errorf("%w: node TPM policy is not enrolled", ErrNodeEvidenceVerification)
	}
	if subtle.ConstantTimeCompare(
		[]byte(strings.TrimSpace(enrollment.NodeUID)),
		[]byte(submission.NodeUID),
	) != 1 {
		return fmt.Errorf("%w: node UID does not match enrollment", ErrNodeEvidenceVerification)
	}
	evidence, err := tpmlocal.UnmarshalEvidence(submission.Payload)
	if err != nil {
		return fmt.Errorf("%w: invalid TPM evidence", ErrNodeEvidenceVerification)
	}
	if subtle.ConstantTimeCompare([]byte(evidence.ChallengeID), []byte(submission.ChallengeID)) != 1 {
		return fmt.Errorf("%w: TPM challenge ID mismatch", ErrNodeEvidenceVerification)
	}
	if _, err := tpmlocal.EvaluatePolicy(evidence, nonce, enrollment.TPMPolicy); err != nil {
		return fmt.Errorf("%w: TPM policy rejected evidence", ErrNodeEvidenceVerification)
	}
	return nil
}

func nodeEvidencePayloadHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
