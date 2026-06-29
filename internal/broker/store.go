package broker

import (
	"context"
	"errors"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

var (
	// ErrSubjectNotFound indicates an unknown subject.
	ErrSubjectNotFound = errors.New("subject not found")
	// ErrSubjectRevoked indicates a revoked subject.
	ErrSubjectRevoked = errors.New("subject revoked")
	// ErrChallengeNotFound indicates an unknown challenge.
	ErrChallengeNotFound = errors.New("challenge not found")
	// ErrChallengeExpired indicates an expired challenge.
	ErrChallengeExpired = errors.New("challenge expired")
	// ErrChallengeReplayed indicates a consumed challenge.
	ErrChallengeReplayed = errors.New("challenge already consumed")
	// ErrChallengeMismatch indicates challenge scope does not match the request.
	ErrChallengeMismatch = errors.New("challenge scope mismatch")
	// ErrRotationNotFound indicates an unknown rotation operation.
	ErrRotationNotFound = errors.New("rotation operation not found")
	// ErrRotationInProgress indicates another rotation is already started for a keyring.
	ErrRotationInProgress = errors.New("rotation operation already in progress")
	// ErrRotationInvalidTransition indicates a requested rotation transition is not allowed.
	ErrRotationInvalidTransition = errors.New("rotation transition is invalid")
)

// Challenge is broker replay-prevention state.
type Challenge struct {
	ID        string
	Nonce     []byte
	ClusterID string
	Subject   string
	Operation protocolv1.Operation
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Subject is one broker-authorized caller identity.
type Subject struct {
	ClusterID string
	Subject   string
	Revoked   bool
}

// BootstrapKeyringRequest seeds a fresh broker keyring.
type BootstrapKeyringRequest struct {
	ClusterID            string
	KeyID                string
	Profile              string
	PolicyID             string
	Material             []byte
	RecoveryPackageID    string
	RecoveryThreshold    int
	RecoveryShares       int
	RecoveryChecksum     string
	RecoveryMetadataJSON string
	CreatedAt            time.Time
}

// RecoveryPackageRecord stores non-secret recovery metadata.
type RecoveryPackageRecord struct {
	PackageID string
	ClusterID string
	KeyID     string
	Threshold int
	Shares    int
	Checksum  string
	Body      string
	CreatedAt time.Time
}

// EnrollmentRequestRecord stores an enrollment request body.
type EnrollmentRequestRecord struct {
	RequestID string
	ClusterID string
	Subject   string
	Body      string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// EnrollmentGrantRecord stores a one-time enrollment grant body.
type EnrollmentGrantRecord struct {
	GrantID   string
	RequestID string
	ClusterID string
	Subject   string
	Body      string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RotationStatus is the lifecycle state of one key rotation operation.
type RotationStatus string

const (
	// RotationStatusStarted means the new key version exists but is pending.
	RotationStatusStarted RotationStatus = "started"
	// RotationStatusActivated means the pending key was promoted to active.
	RotationStatusActivated RotationStatus = "activated"
	// RotationStatusCancelled means the operation was abandoned before activation.
	RotationStatusCancelled RotationStatus = "cancelled"
)

// RotationStartRequest creates a pending wrapping-key version.
type RotationStartRequest struct {
	OperationID string
	ClusterID   string
	KeyID       string
	PolicyID    string
	Material    []byte
	CreatedAt   time.Time
}

// RotationOperation is durable rotation workflow state.
type RotationOperation struct {
	OperationID string
	ClusterID   string
	KeyID       string
	FromVersion uint32
	ToVersion   uint32
	Status      RotationStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ActivatedAt time.Time
}

// RotationVerificationName identifies one proof point in the rotation workflow.
type RotationVerificationName string

const (
	// RotationVerificationOpenBAORoot records that OpenBao accepted /sys/rotate/root.
	RotationVerificationOpenBAORoot RotationVerificationName = "openbao-root"
	// RotationVerificationRestart records that OpenBao restarted and auto-unsealed.
	RotationVerificationRestart RotationVerificationName = "restart"
	// RotationVerificationKeyVersion is reserved for future BlobInfo key-version proof.
	RotationVerificationKeyVersion RotationVerificationName = "key-version"
)

// RotationVerification is one durable verification signal for a rotation.
type RotationVerification struct {
	OperationID string
	Name        RotationVerificationName
	VerifiedAt  time.Time
	Detail      string
}

// Store persists broker state.
type Store interface {
	Close() error
	BootstrapKeyring(ctx context.Context, request BootstrapKeyringRequest) error
	ConfigureDevelopment(ctx context.Context, config Config, key []byte) error
	LoadKeyring(ctx context.Context, clusterID string) (*keyring.Ring, error)
	KeyVersion(ctx context.Context, ref keyring.KeyRef) (keyring.KeyVersion, error)
	Subject(ctx context.Context, clusterID string, subject string) (Subject, error)
	InsertSubject(ctx context.Context, clusterID string, subject string, now time.Time) error
	RevokeSubject(ctx context.Context, clusterID string, subject string) error
	InsertRecoveryPackage(ctx context.Context, record RecoveryPackageRecord) error
	InsertEnrollmentRequest(ctx context.Context, record EnrollmentRequestRecord) error
	InsertEnrollmentGrant(ctx context.Context, record EnrollmentGrantRecord) error
	ConsumeEnrollmentGrant(ctx context.Context, grantID string, now time.Time) error
	StartRotation(ctx context.Context, request RotationStartRequest) (RotationOperation, error)
	ActivateRotation(ctx context.Context, operationID string, now time.Time) (RotationOperation, error)
	RotationOperation(ctx context.Context, operationID string) (RotationOperation, error)
	RecordRotationVerification(
		ctx context.Context,
		operationID string,
		name RotationVerificationName,
		detail string,
		now time.Time,
	) (RotationVerification, error)
	RotationVerifications(ctx context.Context, operationID string) ([]RotationVerification, error)
	CreateChallenge(ctx context.Context, challenge Challenge) error
	ConsumeChallenge(
		ctx context.Context,
		challengeID string,
		clusterID string,
		subject string,
		operation protocolv1.Operation,
		now time.Time,
	) error
	InsertAuditEvent(ctx context.Context, event AuditEvent) error
	AuditEvents(ctx context.Context) ([]AuditEvent, error)
}
