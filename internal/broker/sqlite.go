package broker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyprotection"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	_ "modernc.org/sqlite"
)

const (
	maxKeyVersion                     = int64(^uint32(0))
	maxNodeEvidenceEnrollmentRevision = 1<<63 - 1
)

// SQLiteStore is the first transactional broker state implementation.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens broker state and initializes the current schema.
func OpenSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.InitializeSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the SQLite database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// InitializeSchema creates the current pre-release schema.
// Preview databases from earlier revisions are intentionally unsupported.
func (s *SQLiteStore) InitializeSchema(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, SchemaSQL()); err != nil {
		return fmt.Errorf("initialize sqlite state: %w", err)
	}
	return nil
}

// SchemaSQL returns the broker SQLite schema.
func SchemaSQL() string {
	return `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS clusters (
  cluster_id TEXT PRIMARY KEY,
  recovery_package_id TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keyrings (
  cluster_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  profile TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (cluster_id, key_id),
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS key_versions (
  cluster_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  protector_profile TEXT NOT NULL,
  protected_format TEXT NOT NULL,
  protected_payload BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (cluster_id, key_id, version),
  FOREIGN KEY (cluster_id, key_id) REFERENCES keyrings(cluster_id, key_id),
  CHECK (version > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS key_versions_one_active
ON key_versions(cluster_id, key_id)
WHERE status = 'active';

CREATE TABLE IF NOT EXISTS rotation_operations (
  operation_id TEXT PRIMARY KEY,
  cluster_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  from_version INTEGER NOT NULL,
  to_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  activated_at TEXT,
  cancelled_at TEXT,
  FOREIGN KEY (cluster_id, key_id) REFERENCES keyrings(cluster_id, key_id),
  FOREIGN KEY (cluster_id, key_id, from_version) REFERENCES key_versions(cluster_id, key_id, version),
  FOREIGN KEY (cluster_id, key_id, to_version) REFERENCES key_versions(cluster_id, key_id, version),
  CHECK (from_version > 0),
  CHECK (to_version > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS rotation_operations_one_started
ON rotation_operations(cluster_id, key_id)
WHERE status = 'started';

CREATE TABLE IF NOT EXISTS rotation_verifications (
  operation_id TEXT NOT NULL,
  name TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  detail TEXT NOT NULL,
  PRIMARY KEY (operation_id, name),
  FOREIGN KEY (operation_id) REFERENCES rotation_operations(operation_id)
);

CREATE TABLE IF NOT EXISTS subjects (
  cluster_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (cluster_id, subject_id),
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS subject_claims (
  cluster_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (cluster_id, subject_id, namespace, name),
  FOREIGN KEY (cluster_id, subject_id) REFERENCES subjects(cluster_id, subject_id)
);

CREATE TABLE IF NOT EXISTS policies (
  cluster_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (cluster_id, policy_id),
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS challenges (
  challenge_id TEXT PRIMARY KEY,
  nonce BLOB NOT NULL UNIQUE,
  cluster_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS recovery_packages (
  package_id TEXT PRIMARY KEY,
  cluster_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  threshold_count INTEGER NOT NULL,
  shares_count INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (cluster_id, key_id) REFERENCES keyrings(cluster_id, key_id)
);

CREATE TABLE IF NOT EXISTS enrollment_requests (
  request_id TEXT PRIMARY KEY,
  cluster_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  body TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS enrollment_grants (
  grant_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  cluster_id TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  body TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (request_id) REFERENCES enrollment_requests(request_id),
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
  audit_id TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  cluster_id TEXT NOT NULL,
  key_id TEXT,
  key_version INTEGER,
  decision TEXT NOT NULL,
  policy_id TEXT,
  reason TEXT NOT NULL,
  evidence_hash TEXT,
  remote_addr TEXT,
  error_code TEXT,
  actor TEXT,
  target TEXT,
  correlation_id TEXT,
  request_id TEXT
);

CREATE TABLE IF NOT EXISTS node_evidence (
  cluster_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  node_uid TEXT,
  provider TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  enrollment_revision INTEGER,
  PRIMARY KEY (cluster_id, node_name),
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id)
);

CREATE INDEX IF NOT EXISTS node_evidence_expires_at
ON node_evidence(cluster_id, expires_at);

CREATE TABLE IF NOT EXISTS node_evidence_enrollments (
  cluster_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  node_uid TEXT NOT NULL,
  provider TEXT NOT NULL,
  tpm_policy TEXT NOT NULL,
  revision INTEGER NOT NULL,
  enrolled_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY (cluster_id, node_name),
  FOREIGN KEY (cluster_id) REFERENCES clusters(cluster_id),
  CHECK (revision > 0)
);

CREATE TABLE IF NOT EXISTS node_evidence_publishers (
  cluster_id TEXT NOT NULL,
  node_name TEXT NOT NULL,
  certificate_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (cluster_id, node_name, certificate_sha256),
  FOREIGN KEY (cluster_id, node_name)
    REFERENCES node_evidence_enrollments(cluster_id, node_name)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS node_evidence_publishers_certificate
ON node_evidence_publishers(certificate_sha256);

`
}

// BootstrapKeyring seeds a fresh broker keyring and optional recovery metadata.
func (s *SQLiteStore) BootstrapKeyring(ctx context.Context, request BootstrapKeyringRequest) error {
	if err := request.Key.Validate(); err != nil {
		return err
	}
	if request.Key.Status != keyring.StatusActive || request.Key.Ref.Version != 1 {
		return errors.New("bootstrap key must be active version 1")
	}
	now := request.CreatedAt.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin keyring bootstrap transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO clusters(cluster_id, recovery_package_id, created_at) VALUES (?, ?, ?)`,
		request.Key.Ref.ClusterID,
		nullableString(request.RecoveryPackageID),
		now,
	); err != nil {
		return fmt.Errorf("insert cluster: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO keyrings(cluster_id, key_id, profile, created_at) VALUES (?, ?, ?, ?)`,
		request.Key.Ref.ClusterID,
		request.Key.Ref.KeyID,
		request.Key.ProtectorProfile,
		now,
	); err != nil {
		return fmt.Errorf("insert keyring: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO key_versions(cluster_id, key_id, version, status, algorithm, policy_id,
		   protector_profile, protected_format, protected_payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		request.Key.Ref.ClusterID,
		request.Key.Ref.KeyID,
		request.Key.Ref.Version,
		string(request.Key.Status),
		string(request.Key.Algorithm),
		request.Key.PolicyID,
		request.Key.ProtectorProfile,
		request.Key.Format,
		request.Key.Payload,
		now,
	); err != nil {
		return fmt.Errorf("insert key version: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO policies(cluster_id, policy_id, body, created_at) VALUES (?, ?, ?, ?)`,
		request.Key.Ref.ClusterID,
		request.Key.PolicyID,
		"default-deny-with-enrolled-subjects",
		now,
	); err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}
	if request.RecoveryPackageID != "" {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO recovery_packages(package_id, cluster_id, key_id, threshold_count, shares_count,
			 checksum, body, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			request.RecoveryPackageID,
			request.Key.Ref.ClusterID,
			request.Key.Ref.KeyID,
			request.RecoveryThreshold,
			request.RecoveryShares,
			request.RecoveryChecksum,
			request.RecoveryMetadataJSON,
			now,
		); err != nil {
			return fmt.Errorf("insert recovery package: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit keyring bootstrap transaction: %w", err)
	}
	return nil
}

// ConfigureDevelopment seeds the explicit development subject and keyring.
func (s *SQLiteStore) ConfigureDevelopment(
	ctx context.Context,
	config Config,
	key keyprotection.ProtectedKey,
) error {
	if err := validateDevelopmentProtectedKey(config, key); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin development seed transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO clusters(cluster_id, created_at) VALUES (?, ?)`,
		config.ClusterID,
		now,
	); err != nil {
		return fmt.Errorf("insert cluster: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO keyrings(cluster_id, key_id, profile, created_at) VALUES (?, ?, ?, ?)`,
		config.ClusterID,
		config.KeyID,
		config.Profile(),
		now,
	); err != nil {
		return fmt.Errorf("insert keyring: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO key_versions(cluster_id, key_id, version, status, algorithm, policy_id,
		   protector_profile, protected_format, protected_payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		config.ClusterID,
		config.KeyID,
		key.Ref.Version,
		string(key.Status),
		string(key.Algorithm),
		key.PolicyID,
		key.ProtectorProfile,
		key.Format,
		key.Payload,
		now,
	); err != nil {
		return fmt.Errorf("insert key version: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO policies(cluster_id, policy_id, body, created_at) VALUES (?, ?, ?, ?)`,
		config.ClusterID,
		config.Policy(),
		"default-deny-with-development-subject",
		now,
	); err != nil {
		return fmt.Errorf("insert policy: %w", err)
	}
	for _, subject := range config.DevelopmentSubjects() {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO subjects(cluster_id, subject_id, revoked, created_at) VALUES (?, ?, 0, ?)`,
			config.ClusterID,
			subject,
			now,
		); err != nil {
			return fmt.Errorf("insert development subject: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit development seed transaction: %w", err)
	}
	return nil
}

func validateDevelopmentProtectedKey(config Config, key keyprotection.ProtectedKey) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if key.Ref.ClusterID != config.ClusterID || key.Ref.KeyID != config.KeyID ||
		key.Ref.Version != 1 || key.Status != keyring.StatusActive ||
		key.PolicyID != config.Policy() || key.ProtectorProfile != config.Profile() {
		return errors.New("development protected key does not match broker configuration")
	}
	return nil
}

// ProtectedKeys loads durable protected key records for one cluster.
func (s *SQLiteStore) ProtectedKeys(
	ctx context.Context,
	clusterID string,
) ([]keyprotection.ProtectedKey, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT key_id, version, status, algorithm, policy_id,
		        protector_profile, protected_format, protected_payload
		 FROM key_versions
		 WHERE cluster_id = ?
		 ORDER BY key_id, version`,
		clusterID,
	)
	if err != nil {
		return nil, fmt.Errorf("query key versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	records := make([]keyprotection.ProtectedKey, 0)
	for rows.Next() {
		var record keyprotection.ProtectedKey
		var versionNumber int64
		if err := rows.Scan(
			&record.Ref.KeyID,
			&versionNumber,
			&record.Status,
			&record.Algorithm,
			&record.PolicyID,
			&record.ProtectorProfile,
			&record.Format,
			&record.Payload,
		); err != nil {
			return nil, fmt.Errorf("scan key version: %w", err)
		}
		record.Ref.ClusterID = clusterID
		if versionNumber <= 0 || versionNumber > maxKeyVersion {
			return nil, fmt.Errorf("key version exceeds uint32: %d", versionNumber)
		}
		record.Ref.Version = uint32(versionNumber)
		if err := record.Validate(); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate key versions: %w", err)
	}
	if len(records) == 0 {
		return nil, keyring.ErrKeyNotFound
	}
	return records, nil
}

// ProtectedKey loads one durable protected key record.
func (s *SQLiteStore) ProtectedKey(
	ctx context.Context,
	ref keyring.KeyRef,
) (keyprotection.ProtectedKey, error) {
	var record keyprotection.ProtectedKey
	err := s.db.QueryRowContext(
		ctx,
		`SELECT status, algorithm, policy_id, protector_profile, protected_format, protected_payload
		 FROM key_versions
		 WHERE cluster_id = ? AND key_id = ? AND version = ?`,
		ref.ClusterID,
		ref.KeyID,
		ref.Version,
	).Scan(
		&record.Status,
		&record.Algorithm,
		&record.PolicyID,
		&record.ProtectorProfile,
		&record.Format,
		&record.Payload,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return keyprotection.ProtectedKey{}, keyring.ErrKeyNotFound
	}
	if err != nil {
		return keyprotection.ProtectedKey{}, fmt.Errorf("query key version: %w", err)
	}
	record.Ref = ref
	if err := record.Validate(); err != nil {
		return keyprotection.ProtectedKey{}, err
	}
	return record, nil
}

// Subject loads one subject.
func (s *SQLiteStore) Subject(ctx context.Context, clusterID string, subject string) (Subject, error) {
	var revoked int
	err := s.db.QueryRowContext(
		ctx,
		`SELECT revoked FROM subjects WHERE cluster_id = ? AND subject_id = ?`,
		clusterID,
		subject,
	).Scan(&revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Subject{}, ErrSubjectNotFound
	}
	if err != nil {
		return Subject{}, fmt.Errorf("query subject: %w", err)
	}
	if revoked != 0 {
		return Subject{ClusterID: clusterID, Subject: subject, Revoked: true}, ErrSubjectRevoked
	}
	return Subject{ClusterID: clusterID, Subject: subject}, nil
}

// InsertSubject records an allowed broker subject.
func (s *SQLiteStore) InsertSubject(ctx context.Context, clusterID string, subject string, now time.Time) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO subjects(cluster_id, subject_id, revoked, created_at) VALUES (?, ?, 0, ?)`,
		clusterID,
		subject,
		now.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert subject: %w", err)
	}
	return nil
}

// RevokeSubject marks one subject revoked.
func (s *SQLiteStore) RevokeSubject(ctx context.Context, clusterID string, subject string) error {
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE subjects SET revoked = 1, revoked_at = ? WHERE cluster_id = ? AND subject_id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano),
		clusterID,
		subject,
	)
	if err != nil {
		return fmt.Errorf("revoke subject: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read revoke result: %w", err)
	}
	if affected == 0 {
		return ErrSubjectNotFound
	}
	return nil
}

// InsertRecoveryPackage stores non-secret recovery metadata.
func (s *SQLiteStore) InsertRecoveryPackage(ctx context.Context, record RecoveryPackageRecord) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO recovery_packages(package_id, cluster_id, key_id, threshold_count, shares_count,
		 checksum, body, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		record.PackageID,
		record.ClusterID,
		record.KeyID,
		record.Threshold,
		record.Shares,
		record.Checksum,
		record.Body,
		record.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert recovery package: %w", err)
	}
	return nil
}

// InsertEnrollmentRequest stores an enrollment request.
func (s *SQLiteStore) InsertEnrollmentRequest(ctx context.Context, record EnrollmentRequestRecord) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT OR REPLACE INTO enrollment_requests(request_id, cluster_id, subject_id, body, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		record.RequestID,
		record.ClusterID,
		record.Subject,
		record.Body,
		record.ExpiresAt.UTC().Format(time.RFC3339Nano),
		record.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert enrollment request: %w", err)
	}
	return nil
}

// InsertEnrollmentGrant stores an enrollment grant.
func (s *SQLiteStore) InsertEnrollmentGrant(ctx context.Context, record EnrollmentGrantRecord) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO enrollment_grants(grant_id, request_id, cluster_id, subject_id, body, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		record.GrantID,
		record.RequestID,
		record.ClusterID,
		record.Subject,
		record.Body,
		record.ExpiresAt.UTC().Format(time.RFC3339Nano),
		record.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert enrollment grant: %w", err)
	}
	return nil
}

// ConsumeEnrollmentGrant marks a one-time enrollment grant consumed.
func (s *SQLiteStore) ConsumeEnrollmentGrant(ctx context.Context, grantID string, now time.Time) error {
	var expiresRaw string
	var consumed sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		`SELECT expires_at, consumed_at FROM enrollment_grants WHERE grant_id = ?`,
		grantID,
	).Scan(&expiresRaw, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: enrollment grant not found", ErrChallengeNotFound)
	}
	if err != nil {
		return fmt.Errorf("query enrollment grant: %w", err)
	}
	if consumed.Valid {
		return ErrChallengeReplayed
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return fmt.Errorf("parse enrollment grant expiry: %w", err)
	}
	if !now.Before(expiresAt) {
		return ErrChallengeExpired
	}
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE enrollment_grants SET consumed_at = ? WHERE grant_id = ? AND consumed_at IS NULL`,
		now.UTC().Format(time.RFC3339Nano),
		grantID,
	)
	if err != nil {
		return fmt.Errorf("consume enrollment grant: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read enrollment grant consume result: %w", err)
	}
	if affected == 0 {
		return ErrChallengeReplayed
	}
	return nil
}

// NextRotationKeyRef returns the reference a new pending key must use.
func (s *SQLiteStore) NextRotationKeyRef(
	ctx context.Context,
	clusterID string,
	keyID string,
) (keyring.KeyRef, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return keyring.KeyRef{}, fmt.Errorf("begin next rotation key transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	_, version, err := nextRotationVersions(ctx, tx, clusterID, keyID)
	if err != nil {
		return keyring.KeyRef{}, err
	}
	if err := tx.Commit(); err != nil {
		return keyring.KeyRef{}, fmt.Errorf("commit next rotation key transaction: %w", err)
	}
	return keyring.KeyRef{ClusterID: clusterID, KeyID: keyID, Version: version}, nil
}

// StartRotation creates a pending key version and durable rotation operation.
func (s *SQLiteStore) StartRotation(
	ctx context.Context,
	request RotationStartRequest,
) (RotationOperation, error) {
	if err := validateRotationStart(request); err != nil {
		return RotationOperation{}, err
	}
	now := request.CreatedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RotationOperation{}, fmt.Errorf("begin rotation start transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	ref := request.Key.Ref
	if err := ensureNoStartedRotation(ctx, tx, ref.ClusterID, ref.KeyID); err != nil {
		return RotationOperation{}, err
	}
	fromVersion, toVersion, err := nextRotationVersions(ctx, tx, ref.ClusterID, ref.KeyID)
	if err != nil {
		return RotationOperation{}, err
	}
	if ref.Version != toVersion {
		return RotationOperation{}, fmt.Errorf(
			"%w: pending key version %d does not match next version %d",
			ErrRotationInvalidTransition,
			ref.Version,
			toVersion,
		)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO key_versions(cluster_id, key_id, version, status, algorithm, policy_id,
		   protector_profile, protected_format, protected_payload, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ref.ClusterID,
		ref.KeyID,
		toVersion,
		string(request.Key.Status),
		string(request.Key.Algorithm),
		request.Key.PolicyID,
		request.Key.ProtectorProfile,
		request.Key.Format,
		request.Key.Payload,
		now.Format(time.RFC3339Nano),
	); err != nil {
		return RotationOperation{}, fmt.Errorf("insert pending key version: %w", err)
	}
	operation := RotationOperation{
		OperationID: request.OperationID,
		ClusterID:   ref.ClusterID,
		KeyID:       ref.KeyID,
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Status:      RotationStatusStarted,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO rotation_operations(operation_id, cluster_id, key_id, from_version, to_version,
		 status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		operation.OperationID,
		operation.ClusterID,
		operation.KeyID,
		operation.FromVersion,
		operation.ToVersion,
		string(operation.Status),
		operation.CreatedAt.Format(time.RFC3339Nano),
		operation.UpdatedAt.Format(time.RFC3339Nano),
	); err != nil {
		return RotationOperation{}, fmt.Errorf("insert rotation operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RotationOperation{}, fmt.Errorf("commit rotation start transaction: %w", err)
	}
	return operation, nil
}

// ActivateRotation promotes a pending key and demotes the previous active key.
func (s *SQLiteStore) ActivateRotation(
	ctx context.Context,
	operationID string,
	now time.Time,
) (RotationOperation, error) {
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RotationOperation{}, fmt.Errorf("begin rotation activation transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	operation, err := queryRotationOperationTx(ctx, tx, operationID)
	if err != nil {
		return RotationOperation{}, err
	}
	switch operation.Status {
	case RotationStatusActivated:
		if err := tx.Commit(); err != nil {
			return RotationOperation{}, fmt.Errorf("commit idempotent rotation activation: %w", err)
		}
		return operation, nil
	case RotationStatusStarted:
	default:
		return RotationOperation{}, ErrRotationInvalidTransition
	}
	if err := updateKeyStatus(
		ctx,
		tx,
		operation.ClusterID,
		operation.KeyID,
		operation.FromVersion,
		keyring.StatusActive,
		keyring.StatusDecryptOnly,
	); err != nil {
		return RotationOperation{}, err
	}
	if err := updateKeyStatus(
		ctx,
		tx,
		operation.ClusterID,
		operation.KeyID,
		operation.ToVersion,
		keyring.StatusPending,
		keyring.StatusActive,
	); err != nil {
		return RotationOperation{}, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE rotation_operations
		 SET status = ?, activated_at = ?, updated_at = ?
		 WHERE operation_id = ?`,
		string(RotationStatusActivated),
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		operation.OperationID,
	); err != nil {
		return RotationOperation{}, fmt.Errorf("update rotation operation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RotationOperation{}, fmt.Errorf("commit rotation activation transaction: %w", err)
	}
	operation.Status = RotationStatusActivated
	operation.UpdatedAt = now
	operation.ActivatedAt = now
	return operation, nil
}

// RotationOperation loads one durable rotation operation.
func (s *SQLiteStore) RotationOperation(ctx context.Context, operationID string) (RotationOperation, error) {
	return queryRotationOperation(ctx, s.db, operationID)
}

// RecordRotationVerification records or refreshes one rotation verification signal.
func (s *SQLiteStore) RecordRotationVerification(
	ctx context.Context,
	operationID string,
	name RotationVerificationName,
	detail string,
	now time.Time,
) (RotationVerification, error) {
	if err := validateRotationVerification(name, detail); err != nil {
		return RotationVerification{}, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RotationVerification{}, fmt.Errorf("begin rotation verification transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)
	if _, err := queryRotationOperationTx(ctx, tx, operationID); err != nil {
		return RotationVerification{}, err
	}
	verification := RotationVerification{
		OperationID: operationID,
		Name:        name,
		VerifiedAt:  now,
		Detail:      detail,
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO rotation_verifications(operation_id, name, verified_at, detail)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(operation_id, name) DO UPDATE SET
		   verified_at = excluded.verified_at,
		   detail = excluded.detail`,
		verification.OperationID,
		string(verification.Name),
		verification.VerifiedAt.Format(time.RFC3339Nano),
		verification.Detail,
	); err != nil {
		return RotationVerification{}, fmt.Errorf("record rotation verification: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return RotationVerification{}, fmt.Errorf("commit rotation verification transaction: %w", err)
	}
	return verification, nil
}

// RotationVerifications loads all verification signals for one rotation operation.
func (s *SQLiteStore) RotationVerifications(ctx context.Context, operationID string) ([]RotationVerification, error) {
	if _, err := s.RotationOperation(ctx, operationID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT operation_id, name, verified_at, detail
		 FROM rotation_verifications
		 WHERE operation_id = ?
		 ORDER BY name`,
		operationID,
	)
	if err != nil {
		return nil, fmt.Errorf("query rotation verifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	verifications := make([]RotationVerification, 0)
	for rows.Next() {
		var verification RotationVerification
		var name string
		var verifiedAtRaw string
		if err := rows.Scan(
			&verification.OperationID,
			&name,
			&verifiedAtRaw,
			&verification.Detail,
		); err != nil {
			return nil, fmt.Errorf("scan rotation verification: %w", err)
		}
		verification.Name = RotationVerificationName(name)
		verifiedAt, parseErr := time.Parse(time.RFC3339Nano, verifiedAtRaw)
		if parseErr != nil {
			return nil, fmt.Errorf("parse rotation verification time: %w", parseErr)
		}
		verification.VerifiedAt = verifiedAt
		verifications = append(verifications, verification)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rotation verifications: %w", err)
	}
	return verifications, nil
}

// CreateChallenge stores one broker challenge.
func (s *SQLiteStore) CreateChallenge(ctx context.Context, challenge Challenge) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO challenges(challenge_id, nonce, cluster_id, subject_id, operation, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		challenge.ID,
		challenge.Nonce,
		challenge.ClusterID,
		challenge.Subject,
		challenge.Operation.String(),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
		challenge.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert challenge: %w", err)
	}
	return nil
}

// ChallengeNonce returns the nonce after validating challenge scope, freshness, and replay state.
func (s *SQLiteStore) ChallengeNonce(
	ctx context.Context,
	challengeID string,
	clusterID string,
	subject string,
	operation protocolv1.Operation,
	now time.Time,
) ([]byte, error) {
	var nonce []byte
	var storedCluster string
	var storedSubject string
	var storedOperation string
	var expiresRaw string
	var consumed sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		`SELECT nonce, cluster_id, subject_id, operation, expires_at, consumed_at
		 FROM challenges
		 WHERE challenge_id = ?`,
		challengeID,
	).Scan(&nonce, &storedCluster, &storedSubject, &storedOperation, &expiresRaw, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query challenge nonce: %w", err)
	}
	if storedCluster != clusterID || storedSubject != subject || storedOperation != operation.String() {
		return nil, ErrChallengeMismatch
	}
	if consumed.Valid {
		return nil, ErrChallengeReplayed
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return nil, fmt.Errorf("parse challenge expiry: %w", err)
	}
	if !now.Before(expiresAt) {
		return nil, ErrChallengeExpired
	}
	return slices.Clone(nonce), nil
}

// ConsumeChallenge validates scope and consumes one challenge exactly once.
func (s *SQLiteStore) ConsumeChallenge(
	ctx context.Context,
	challengeID string,
	clusterID string,
	subject string,
	operation protocolv1.Operation,
	now time.Time,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin challenge consume transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	var storedCluster string
	var storedSubject string
	var storedOperation string
	var expiresRaw string
	var consumed sql.NullString
	err = tx.QueryRowContext(
		ctx,
		`SELECT cluster_id, subject_id, operation, expires_at, consumed_at
		 FROM challenges
		 WHERE challenge_id = ?`,
		challengeID,
	).Scan(&storedCluster, &storedSubject, &storedOperation, &expiresRaw, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrChallengeNotFound
	}
	if err != nil {
		return fmt.Errorf("query challenge: %w", err)
	}
	if storedCluster != clusterID || storedSubject != subject || storedOperation != operation.String() {
		return ErrChallengeMismatch
	}
	if consumed.Valid {
		return ErrChallengeReplayed
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return fmt.Errorf("parse challenge expiry: %w", err)
	}
	if !now.Before(expiresAt) {
		return ErrChallengeExpired
	}

	result, err := tx.ExecContext(
		ctx,
		`UPDATE challenges SET consumed_at = ? WHERE challenge_id = ? AND consumed_at IS NULL`,
		now.UTC().Format(time.RFC3339Nano),
		challengeID,
	)
	if err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read consume result: %w", err)
	}
	if affected == 0 {
		return ErrChallengeReplayed
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit challenge consume transaction: %w", err)
	}
	return nil
}

// EnrollNodeEvidence creates or replaces broker-owned trust for one node.
func (s *SQLiteStore) EnrollNodeEvidence(
	ctx context.Context,
	request nodeevidence.EnrollmentRequest,
) (nodeevidence.Enrollment, error) {
	request, err := nodeevidence.NormalizeEnrollmentRequest(request)
	if err != nil {
		return nodeevidence.Enrollment{}, err
	}
	policyJSON, err := json.Marshal(request.TPMPolicy)
	if err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("marshal node evidence enrollment policy: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("begin node evidence enrollment transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	var currentRevision int64
	err = tx.QueryRowContext(
		ctx,
		`SELECT revision FROM node_evidence_enrollments WHERE cluster_id = ? AND node_name = ?`,
		request.ClusterID,
		request.NodeName,
	).Scan(&currentRevision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nodeevidence.Enrollment{}, fmt.Errorf("query node evidence enrollment revision: %w", err)
	}
	if currentRevision == maxNodeEvidenceEnrollmentRevision {
		return nodeevidence.Enrollment{}, errors.New("node evidence enrollment revision exhausted")
	}
	revision := currentRevision + 1
	now := request.EnrolledAt.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO node_evidence_enrollments(
		   cluster_id, node_name, node_uid, provider, tpm_policy, revision,
		   enrolled_at, updated_at, revoked_at
		 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(cluster_id, node_name) DO UPDATE SET
		   node_uid = excluded.node_uid,
		   provider = excluded.provider,
		   tpm_policy = excluded.tpm_policy,
		   revision = excluded.revision,
		   enrolled_at = excluded.enrolled_at,
		   updated_at = excluded.updated_at,
		   revoked_at = NULL`,
		request.ClusterID,
		request.NodeName,
		request.NodeUID,
		request.Provider,
		string(policyJSON),
		revision,
		now,
		now,
	); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("upsert node evidence enrollment: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM node_evidence_publishers WHERE cluster_id = ? AND node_name = ?`,
		request.ClusterID,
		request.NodeName,
	); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("replace node evidence publishers: %w", err)
	}
	for _, certificateHash := range request.PublisherCertificateHashes {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO node_evidence_publishers(
			   cluster_id, node_name, certificate_sha256, created_at
			 ) VALUES (?, ?, ?, ?)`,
			request.ClusterID,
			request.NodeName,
			certificateHash,
			now,
		); err != nil {
			return nodeevidence.Enrollment{}, fmt.Errorf("insert node evidence publisher: %w", err)
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM node_evidence WHERE cluster_id = ? AND node_name = ?`,
		request.ClusterID,
		request.NodeName,
	); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("invalidate node evidence after enrollment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("commit node evidence enrollment: %w", err)
	}
	revisionNumber := uint64(revision) // #nosec G115 -- SQL revision is positive and below int64 maximum.
	return nodeevidence.NormalizeEnrollment(nodeevidence.Enrollment{
		ClusterID:                  request.ClusterID,
		NodeName:                   request.NodeName,
		NodeUID:                    request.NodeUID,
		Provider:                   request.Provider,
		TPMPolicy:                  request.TPMPolicy,
		PublisherCertificateHashes: request.PublisherCertificateHashes,
		Revision:                   revisionNumber,
		EnrolledAt:                 request.EnrolledAt,
		UpdatedAt:                  request.EnrolledAt,
	})
}

// RevokeNodeEvidence revokes one enrollment and atomically removes verified evidence.
func (s *SQLiteStore) RevokeNodeEvidence(
	ctx context.Context,
	clusterID string,
	nodeName string,
	now time.Time,
) (nodeevidence.Enrollment, error) {
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	if clusterID == "" || nodeName == "" || now.IsZero() {
		return nodeevidence.Enrollment{}, fmt.Errorf(
			"%w: cluster_id, node_name, and revocation time are required",
			nodeevidence.ErrInvalidEnrollment,
		)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("begin node evidence revocation transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)
	enrollment, err := scanNodeEvidenceEnrollment(tx.QueryRowContext(
		ctx,
		`SELECT cluster_id, node_name, node_uid, provider, tpm_policy, revision,
		        enrolled_at, updated_at, revoked_at
		 FROM node_evidence_enrollments
		 WHERE cluster_id = ? AND node_name = ?`,
		clusterID,
		nodeName,
	))
	if err != nil {
		return nodeevidence.Enrollment{}, err
	}
	if !enrollment.Active() {
		return enrollment, nodeevidence.ErrEnrollmentRevoked
	}
	if enrollment.Revision >= maxNodeEvidenceEnrollmentRevision {
		return nodeevidence.Enrollment{}, errors.New("node evidence enrollment revision exhausted")
	}
	revokedAt := now.UTC()
	enrollment.Revision++
	enrollment.UpdatedAt = revokedAt
	enrollment.RevokedAt = revokedAt
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE node_evidence_enrollments
		 SET revision = ?, updated_at = ?, revoked_at = ?
		 WHERE cluster_id = ? AND node_name = ? AND revoked_at IS NULL`,
		enrollment.Revision,
		revokedAt.Format(time.RFC3339Nano),
		revokedAt.Format(time.RFC3339Nano),
		clusterID,
		nodeName,
	); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("revoke node evidence enrollment: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM node_evidence WHERE cluster_id = ? AND node_name = ?`,
		clusterID,
		nodeName,
	); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("invalidate revoked node evidence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("commit node evidence revocation: %w", err)
	}
	enrollment.PublisherCertificateHashes, err = s.nodeEvidencePublisherHashes(ctx, clusterID, nodeName)
	if err != nil {
		return nodeevidence.Enrollment{}, err
	}
	return nodeevidence.NormalizeEnrollment(enrollment)
}

// ActiveNodeEvidenceEnrollment returns active broker-owned trust for one node.
func (s *SQLiteStore) ActiveNodeEvidenceEnrollment(
	ctx context.Context,
	clusterID string,
	nodeName string,
) (nodeevidence.Enrollment, error) {
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	enrollment, err := scanNodeEvidenceEnrollment(s.db.QueryRowContext(
		ctx,
		`SELECT cluster_id, node_name, node_uid, provider, tpm_policy, revision,
		        enrolled_at, updated_at, revoked_at
		 FROM node_evidence_enrollments
		 WHERE cluster_id = ? AND node_name = ?`,
		clusterID,
		nodeName,
	))
	if err != nil {
		return nodeevidence.Enrollment{}, err
	}
	if !enrollment.Active() {
		return enrollment, nodeevidence.ErrEnrollmentRevoked
	}
	enrollment.PublisherCertificateHashes, err = s.nodeEvidencePublisherHashes(ctx, clusterID, nodeName)
	if err != nil {
		return nodeevidence.Enrollment{}, err
	}
	return nodeevidence.NormalizeEnrollment(enrollment)
}

// ListNodeEvidenceEnrollments returns node trust records for one cluster.
func (s *SQLiteStore) ListNodeEvidenceEnrollments(
	ctx context.Context,
	clusterID string,
	nodeName string,
	includeRevoked bool,
) ([]nodeevidence.Enrollment, error) {
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT cluster_id, node_name, node_uid, provider, tpm_policy, revision,
		        enrolled_at, updated_at, revoked_at
		 FROM node_evidence_enrollments
		 WHERE cluster_id = ?
		   AND (? = '' OR node_name = ?)
		   AND (? OR revoked_at IS NULL)
		 ORDER BY node_name`,
		clusterID,
		nodeName,
		nodeName,
		includeRevoked,
	)
	if err != nil {
		return nil, fmt.Errorf("query node evidence enrollments: %w", err)
	}
	enrollments := make([]nodeevidence.Enrollment, 0)
	for rows.Next() {
		enrollment, scanErr := scanNodeEvidenceEnrollment(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		enrollments = append(enrollments, enrollment)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate node evidence enrollments: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close node evidence enrollment rows: %w", err)
	}
	if len(enrollments) == 0 {
		return nil, nodeevidence.ErrEnrollmentNotFound
	}
	for i := range enrollments {
		enrollments[i].PublisherCertificateHashes, err = s.nodeEvidencePublisherHashes(
			ctx,
			enrollments[i].ClusterID,
			enrollments[i].NodeName,
		)
		if err != nil {
			return nil, err
		}
		enrollments[i], err = nodeevidence.NormalizeEnrollment(enrollments[i])
		if err != nil {
			return nil, err
		}
	}
	return enrollments, nil
}

// PutEnrolledNodeEvidence stores evidence only for the still-active enrollment revision.
func (s *SQLiteStore) PutEnrolledNodeEvidence(
	ctx context.Context,
	evidence NodeEvidence,
	revision uint64,
) error {
	normalized, err := normalizeNodeEvidence(evidence)
	if err != nil {
		return err
	}
	if revision == 0 || revision > maxNodeEvidenceEnrollmentRevision {
		return nodeevidence.ErrEnrollmentChanged
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrolled node evidence transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)
	var currentRevision int64
	var nodeUID string
	var provider string
	var revokedAt sql.NullString
	err = tx.QueryRowContext(
		ctx,
		`SELECT revision, node_uid, provider, revoked_at
		 FROM node_evidence_enrollments
		 WHERE cluster_id = ? AND node_name = ?`,
		normalized.ClusterID,
		normalized.NodeName,
	).Scan(&currentRevision, &nodeUID, &provider, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nodeevidence.ErrEnrollmentChanged
	}
	if err != nil {
		return fmt.Errorf("query active node evidence enrollment revision: %w", err)
	}
	revisionNumber := int64(revision) // #nosec G115 -- revision is bounded by maxNodeEvidenceEnrollmentRevision above.
	if currentRevision <= 0 || revokedAt.Valid || currentRevision != revisionNumber ||
		nodeUID != normalized.NodeUID || provider != normalized.Provider {
		return nodeevidence.ErrEnrollmentChanged
	}
	if err := upsertNodeEvidence(ctx, tx, normalized, sql.NullInt64{Int64: currentRevision, Valid: true}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enrolled node evidence: %w", err)
	}
	return nil
}

// PutNodeEvidence stores or replaces broker-trusted node evidence.
func (s *SQLiteStore) PutNodeEvidence(ctx context.Context, evidence NodeEvidence) error {
	normalized, err := normalizeNodeEvidence(evidence)
	if err != nil {
		return err
	}
	if normalized.Provider == nodeevidence.ProviderTPM2Quote {
		return fmt.Errorf(
			"%w: TPM evidence requires an active enrollment revision",
			nodeevidence.ErrEnrollmentChanged,
		)
	}
	return upsertNodeEvidence(ctx, s.db, normalized, sql.NullInt64{})
}

type nodeEvidenceExecer interface {
	//nolint:forbidigo // Mirrors database/sql's variadic adapter boundary.
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func upsertNodeEvidence(
	ctx context.Context,
	execer nodeEvidenceExecer,
	normalized NodeEvidence,
	enrollmentRevision sql.NullInt64,
) error {
	_, err := execer.ExecContext(
		ctx,
		`INSERT INTO node_evidence(
		   cluster_id, node_name, node_uid, provider, evidence_hash, collected_at, expires_at,
		   updated_at, enrollment_revision
		 )
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(cluster_id, node_name) DO UPDATE SET
		   node_uid = excluded.node_uid,
		   provider = excluded.provider,
		   evidence_hash = excluded.evidence_hash,
		   collected_at = excluded.collected_at,
		   expires_at = excluded.expires_at,
		   updated_at = excluded.updated_at,
		   enrollment_revision = excluded.enrollment_revision`,
		normalized.ClusterID,
		normalized.NodeName,
		nullableString(normalized.NodeUID),
		normalized.Provider,
		normalized.EvidenceHash,
		normalized.CollectedAt.UTC().Format(time.RFC3339Nano),
		normalized.ExpiresAt.UTC().Format(time.RFC3339Nano),
		time.Now().UTC().Format(time.RFC3339Nano),
		enrollmentRevision,
	)
	if err != nil {
		return fmt.Errorf("upsert node evidence: %w", err)
	}
	return nil
}

func (s *SQLiteStore) nodeEvidencePublisherHashes(
	ctx context.Context,
	clusterID string,
	nodeName string,
) ([]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT certificate_sha256
		 FROM node_evidence_publishers
		 WHERE cluster_id = ? AND node_name = ?
		 ORDER BY certificate_sha256`,
		clusterID,
		nodeName,
	)
	if err != nil {
		return nil, fmt.Errorf("query node evidence publishers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	hashes := make([]string, 0)
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("scan node evidence publisher: %w", err)
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node evidence publishers: %w", err)
	}
	return hashes, nil
}

// FreshNodeEvidence returns stored node evidence if it exists and has not expired.
func (s *SQLiteStore) FreshNodeEvidence(
	ctx context.Context,
	clusterID string,
	nodeName string,
	now time.Time,
) (NodeEvidence, error) {
	if now.IsZero() {
		now = time.Now()
	}
	evidence, err := s.NodeEvidence(ctx, clusterID, nodeName)
	if err != nil {
		return NodeEvidence{}, err
	}
	if !evidence.ExpiresAt.After(now) {
		return evidence, ErrNodeEvidenceStale
	}
	return evidence, nil
}

// NodeEvidence returns stored node evidence without enforcing freshness.
func (s *SQLiteStore) NodeEvidence(ctx context.Context, clusterID string, nodeName string) (NodeEvidence, error) {
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	return scanNodeEvidence(s.db.QueryRowContext(
		ctx,
		`SELECT cluster_id, node_name, node_uid, provider, evidence_hash, collected_at, expires_at
		 FROM node_evidence
		 WHERE cluster_id = ? AND node_name = ?`,
		clusterID,
		nodeName,
	))
}

// ListNodeEvidence returns stored evidence for one cluster, optionally filtered by node name.
func (s *SQLiteStore) ListNodeEvidence(
	ctx context.Context,
	clusterID string,
	nodeName string,
) ([]NodeEvidence, error) {
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	var rows *sql.Rows
	var err error
	if nodeName != "" {
		rows, err = s.db.QueryContext(
			ctx,
			`SELECT cluster_id, node_name, node_uid, provider, evidence_hash, collected_at, expires_at
			 FROM node_evidence
			 WHERE cluster_id = ? AND node_name = ?
			 ORDER BY node_name`,
			clusterID,
			nodeName,
		)
	} else {
		rows, err = s.db.QueryContext(
			ctx,
			`SELECT cluster_id, node_name, node_uid, provider, evidence_hash, collected_at, expires_at
			 FROM node_evidence
			 WHERE cluster_id = ?
			 ORDER BY node_name`,
			clusterID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("query node evidence: %w", err)
	}
	defer func() { _ = rows.Close() }()

	records := make([]NodeEvidence, 0)
	for rows.Next() {
		evidence, err := scanNodeEvidence(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, evidence)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node evidence: %w", err)
	}
	if len(records) == 0 {
		return nil, ErrNodeEvidenceNotFound
	}
	return records, nil
}

// PruneNodeEvidence deletes node evidence that expired before the supplied cutoff.
func (s *SQLiteStore) PruneNodeEvidence(
	ctx context.Context,
	clusterID string,
	expiredBefore time.Time,
) (int64, error) {
	clusterID = strings.TrimSpace(clusterID)
	if expiredBefore.IsZero() {
		expiredBefore = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin node evidence prune transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	rows, err := tx.QueryContext(
		ctx,
		`SELECT node_name, expires_at
		 FROM node_evidence
		 WHERE cluster_id = ?`,
		clusterID,
	)
	if err != nil {
		return 0, fmt.Errorf("query node evidence for prune: %w", err)
	}
	var expired []string
	for rows.Next() {
		var nodeName string
		var expiresRaw string
		if err := rows.Scan(&nodeName, &expiresRaw); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("scan node evidence for prune: %w", err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
		if err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("parse node evidence prune expires_at: %w", err)
		}
		if expiresAt.Before(expiredBefore) {
			expired = append(expired, nodeName)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, fmt.Errorf("iterate node evidence for prune: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("close node evidence prune rows: %w", err)
	}

	var removed int64
	for _, nodeName := range expired {
		result, err := tx.ExecContext(
			ctx,
			`DELETE FROM node_evidence WHERE cluster_id = ? AND node_name = ?`,
			clusterID,
			nodeName,
		)
		if err != nil {
			return 0, fmt.Errorf("delete pruned node evidence: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("read pruned node evidence result: %w", err)
		}
		removed += affected
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit node evidence prune transaction: %w", err)
	}
	return removed, nil
}

// InsertAuditEvent stores an audit event in SQLite.
func (s *SQLiteStore) InsertAuditEvent(ctx context.Context, event AuditEvent) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO audit_events(audit_id, occurred_at, subject_id, operation, cluster_id, key_id, key_version,
		 decision, policy_id, reason, evidence_hash, remote_addr, error_code, actor, target, correlation_id, request_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.AuditID,
		event.Time,
		event.Subject,
		event.Operation,
		event.ClusterID,
		event.KeyID,
		event.KeyVersion,
		event.Decision,
		event.PolicyID,
		event.Reason,
		event.EvidenceHash,
		event.RemoteAddress,
		event.ErrorCode,
		event.Actor,
		event.Target,
		event.CorrelationID,
		event.RequestID,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// AuditEvents returns stored audit events for tests and diagnostics.
func (s *SQLiteStore) AuditEvents(ctx context.Context) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT audit_id, occurred_at, subject_id, operation, cluster_id, key_id, key_version,
		 decision, policy_id, reason, evidence_hash, remote_addr, error_code, actor, target,
		 correlation_id, request_id
		 FROM audit_events
		 ORDER BY occurred_at, audit_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]AuditEvent, 0)
	for rows.Next() {
		event := AuditEvent{SchemaVersion: 1}
		if err := rows.Scan(
			&event.AuditID,
			&event.Time,
			&event.Subject,
			&event.Operation,
			&event.ClusterID,
			&event.KeyID,
			&event.KeyVersion,
			&event.Decision,
			&event.PolicyID,
			&event.Reason,
			&event.EvidenceHash,
			&event.RemoteAddress,
			&event.ErrorCode,
			&event.Actor,
			&event.Target,
			&event.CorrelationID,
			&event.RequestID,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}

type rowQuerier interface {
	//nolint:forbidigo // Mirrors database/sql's variadic argument boundary for transaction helpers.
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func ensureNoStartedRotation(ctx context.Context, tx *sql.Tx, clusterID string, keyID string) error {
	var operationID string
	err := tx.QueryRowContext(
		ctx,
		`SELECT operation_id
		 FROM rotation_operations
		 WHERE cluster_id = ? AND key_id = ? AND status = ?
		 LIMIT 1`,
		clusterID,
		keyID,
		string(RotationStatusStarted),
	).Scan(&operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("query started rotation operation: %w", err)
	}
	return fmt.Errorf("%w: %s", ErrRotationInProgress, operationID)
}

func nextRotationVersions(ctx context.Context, tx *sql.Tx, clusterID string, keyID string) (uint32, uint32, error) {
	var activeVersion int64
	err := tx.QueryRowContext(
		ctx,
		`SELECT version
		 FROM key_versions
		 WHERE cluster_id = ? AND key_id = ? AND status = ?`,
		clusterID,
		keyID,
		string(keyring.StatusActive),
	).Scan(&activeVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, keyring.ErrKeyNotUsable
	}
	if err != nil {
		return 0, 0, fmt.Errorf("query active key version: %w", err)
	}
	var maxVersion int64
	if err := tx.QueryRowContext(
		ctx,
		`SELECT MAX(version)
		 FROM key_versions
		 WHERE cluster_id = ? AND key_id = ?`,
		clusterID,
		keyID,
	).Scan(&maxVersion); err != nil {
		return 0, 0, fmt.Errorf("query max key version: %w", err)
	}
	if maxVersion >= maxKeyVersion {
		return 0, 0, fmt.Errorf("%w: key version limit reached", ErrRotationInvalidTransition)
	}
	fromVersion, err := uint32KeyVersion(activeVersion)
	if err != nil {
		return 0, 0, err
	}
	toVersion, err := uint32KeyVersion(maxVersion + 1)
	if err != nil {
		return 0, 0, err
	}
	return fromVersion, toVersion, nil
}

func updateKeyStatus(
	ctx context.Context,
	tx *sql.Tx,
	clusterID string,
	keyID string,
	version uint32,
	from keyring.Status,
	to keyring.Status,
) error {
	result, err := tx.ExecContext(
		ctx,
		`UPDATE key_versions
		 SET status = ?
		 WHERE cluster_id = ? AND key_id = ? AND version = ? AND status = ?`,
		string(to),
		clusterID,
		keyID,
		version,
		string(from),
	)
	if err != nil {
		return fmt.Errorf("update key version status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read key status update result: %w", err)
	}
	if affected != 1 {
		return ErrRotationInvalidTransition
	}
	return nil
}

func queryRotationOperation(ctx context.Context, db rowQuerier, operationID string) (RotationOperation, error) {
	return scanRotationOperation(db.QueryRowContext(
		ctx,
		`SELECT operation_id, cluster_id, key_id, from_version, to_version, status,
		 created_at, updated_at, activated_at
		 FROM rotation_operations
		 WHERE operation_id = ?`,
		operationID,
	))
}

func queryRotationOperationTx(ctx context.Context, tx *sql.Tx, operationID string) (RotationOperation, error) {
	return queryRotationOperation(ctx, tx, operationID)
}

func scanRotationOperation(row *sql.Row) (RotationOperation, error) {
	var operation RotationOperation
	var fromVersion int64
	var toVersion int64
	var status string
	var createdRaw string
	var updatedRaw string
	var activatedRaw sql.NullString
	err := row.Scan(
		&operation.OperationID,
		&operation.ClusterID,
		&operation.KeyID,
		&fromVersion,
		&toVersion,
		&status,
		&createdRaw,
		&updatedRaw,
		&activatedRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RotationOperation{}, ErrRotationNotFound
	}
	if err != nil {
		return RotationOperation{}, fmt.Errorf("query rotation operation: %w", err)
	}
	var parseErr error
	operation.FromVersion, parseErr = uint32KeyVersion(fromVersion)
	if parseErr != nil {
		return RotationOperation{}, parseErr
	}
	operation.ToVersion, parseErr = uint32KeyVersion(toVersion)
	if parseErr != nil {
		return RotationOperation{}, parseErr
	}
	operation.Status = RotationStatus(status)
	operation.CreatedAt, parseErr = time.Parse(time.RFC3339Nano, createdRaw)
	if parseErr != nil {
		return RotationOperation{}, fmt.Errorf("parse rotation created_at: %w", parseErr)
	}
	operation.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedRaw)
	if parseErr != nil {
		return RotationOperation{}, fmt.Errorf("parse rotation updated_at: %w", parseErr)
	}
	if activatedRaw.Valid {
		operation.ActivatedAt, parseErr = time.Parse(time.RFC3339Nano, activatedRaw.String)
		if parseErr != nil {
			return RotationOperation{}, fmt.Errorf("parse rotation activated_at: %w", parseErr)
		}
	}
	return operation, nil
}

type nodeEvidenceScanner interface {
	//nolint:forbidigo // Mirrors database/sql's Scan variadic boundary for row and rows helpers.
	Scan(dest ...any) error
}

func scanNodeEvidenceEnrollment(scanner nodeEvidenceScanner) (nodeevidence.Enrollment, error) {
	var enrollment nodeevidence.Enrollment
	var policyJSON string
	var revision int64
	var enrolledRaw string
	var updatedRaw string
	var revokedRaw sql.NullString
	err := scanner.Scan(
		&enrollment.ClusterID,
		&enrollment.NodeName,
		&enrollment.NodeUID,
		&enrollment.Provider,
		&policyJSON,
		&revision,
		&enrolledRaw,
		&updatedRaw,
		&revokedRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nodeevidence.Enrollment{}, nodeevidence.ErrEnrollmentNotFound
	}
	if err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("scan node evidence enrollment: %w", err)
	}
	if revision <= 0 {
		return nodeevidence.Enrollment{}, fmt.Errorf("invalid node evidence enrollment revision %d", revision)
	}
	enrollment.Revision = uint64(revision) // #nosec G115 -- non-positive revisions are rejected above.
	if err := json.Unmarshal([]byte(policyJSON), &enrollment.TPMPolicy); err != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("decode node evidence enrollment policy: %w", err)
	}
	var parseErr error
	enrollment.EnrolledAt, parseErr = time.Parse(time.RFC3339Nano, enrolledRaw)
	if parseErr != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("parse node evidence enrollment enrolled_at: %w", parseErr)
	}
	enrollment.UpdatedAt, parseErr = time.Parse(time.RFC3339Nano, updatedRaw)
	if parseErr != nil {
		return nodeevidence.Enrollment{}, fmt.Errorf("parse node evidence enrollment updated_at: %w", parseErr)
	}
	if revokedRaw.Valid {
		enrollment.RevokedAt, parseErr = time.Parse(time.RFC3339Nano, revokedRaw.String)
		if parseErr != nil {
			return nodeevidence.Enrollment{}, fmt.Errorf("parse node evidence enrollment revoked_at: %w", parseErr)
		}
	}
	return enrollment, nil
}

func scanNodeEvidence(scanner nodeEvidenceScanner) (NodeEvidence, error) {
	var evidence NodeEvidence
	var nodeUID sql.NullString
	var collectedRaw string
	var expiresRaw string
	err := scanner.Scan(
		&evidence.ClusterID,
		&evidence.NodeName,
		&nodeUID,
		&evidence.Provider,
		&evidence.EvidenceHash,
		&collectedRaw,
		&expiresRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeEvidence{}, ErrNodeEvidenceNotFound
	}
	if err != nil {
		return NodeEvidence{}, fmt.Errorf("scan node evidence: %w", err)
	}
	if nodeUID.Valid {
		evidence.NodeUID = nodeUID.String
	}
	var parseErr error
	evidence.CollectedAt, parseErr = time.Parse(time.RFC3339Nano, collectedRaw)
	if parseErr != nil {
		return NodeEvidence{}, fmt.Errorf("parse node evidence collected_at: %w", parseErr)
	}
	evidence.ExpiresAt, parseErr = time.Parse(time.RFC3339Nano, expiresRaw)
	if parseErr != nil {
		return NodeEvidence{}, fmt.Errorf("parse node evidence expires_at: %w", parseErr)
	}
	return evidence, nil
}

func uint32KeyVersion(value int64) (uint32, error) {
	if value <= 0 || value > maxKeyVersion {
		return 0, fmt.Errorf("key version exceeds uint32: %d", value)
	}
	return uint32(value), nil
}

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
