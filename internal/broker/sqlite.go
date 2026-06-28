package broker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/dc-tec/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/dc-tec/openbao-attested-unseal/internal/protocol/v1"
	_ "modernc.org/sqlite"
)

const maxKeyVersion = int64(^uint32(0))

// SQLiteStore is the first transactional broker state implementation.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens and migrates broker state.
func OpenSQLiteStore(ctx context.Context, path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the SQLite database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Migrate applies idempotent schema migrations.
func (s *SQLiteStore) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, SchemaSQL()); err != nil {
		return fmt.Errorf("migrate sqlite state: %w", err)
	}
	if err := s.ensureColumn(ctx, "clusters", "recovery_package_id", "TEXT"); err != nil {
		return err
	}
	return nil
}

func (s *SQLiteStore) ensureColumn(ctx context.Context, table string, column string, definition string) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("inspect sqlite table %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var primaryKey int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			return fmt.Errorf("scan sqlite table %s columns: %w", table, err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate sqlite table %s columns: %w", table, err)
	}
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition); err != nil {
		return fmt.Errorf("add sqlite column %s.%s: %w", table, column, err)
	}
	return nil
}

// SchemaSQL returns the broker SQLite schema.
func SchemaSQL() string {
	return `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

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
  material BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (cluster_id, key_id, version),
  FOREIGN KEY (cluster_id, key_id) REFERENCES keyrings(cluster_id, key_id),
  CHECK (version > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS key_versions_one_active
ON key_versions(cluster_id, key_id)
WHERE status = 'active';

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
  error_code TEXT
);

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
`
}

// BootstrapKeyring seeds a fresh broker keyring and optional recovery metadata.
func (s *SQLiteStore) BootstrapKeyring(ctx context.Context, request BootstrapKeyringRequest) error {
	now := request.CreatedAt.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin keyring bootstrap transaction: %w", err)
	}
	defer rollbackUnlessCommitted(tx)

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO clusters(cluster_id, recovery_package_id, created_at) VALUES (?, ?, ?)`,
		request.ClusterID,
		nullableString(request.RecoveryPackageID),
		now,
	); err != nil {
		return fmt.Errorf("insert cluster: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO keyrings(cluster_id, key_id, profile, created_at) VALUES (?, ?, ?, ?)`,
		request.ClusterID,
		request.KeyID,
		request.Profile,
		now,
	); err != nil {
		return fmt.Errorf("insert keyring: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO key_versions(cluster_id, key_id, version, status, algorithm, policy_id, material, created_at)
		 VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
		request.ClusterID,
		request.KeyID,
		string(keyring.StatusActive),
		string(keyring.AlgorithmAES256GCM),
		request.PolicyID,
		request.Material,
		now,
	); err != nil {
		return fmt.Errorf("insert key version: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO policies(cluster_id, policy_id, body, created_at) VALUES (?, ?, ?, ?)`,
		request.ClusterID,
		request.PolicyID,
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
			request.ClusterID,
			request.KeyID,
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
func (s *SQLiteStore) ConfigureDevelopment(ctx context.Context, config Config, material []byte) error {
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
		`INSERT OR IGNORE INTO key_versions(cluster_id, key_id, version, status, algorithm, policy_id, material, created_at)
		 VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
		config.ClusterID,
		config.KeyID,
		string(keyring.StatusActive),
		string(keyring.AlgorithmAES256GCM),
		config.Policy(),
		material,
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

// LoadKeyring loads all key versions for one cluster.
func (s *SQLiteStore) LoadKeyring(ctx context.Context, clusterID string) (*keyring.Ring, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT key_id, version, status, algorithm, policy_id, material
		 FROM key_versions
		 WHERE cluster_id = ?
		 ORDER BY key_id, version`,
		clusterID,
	)
	if err != nil {
		return nil, fmt.Errorf("query key versions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	versions := make([]keyring.KeyVersion, 0)
	for rows.Next() {
		var version keyring.KeyVersion
		var versionNumber int64
		if err := rows.Scan(
			&version.Ref.KeyID,
			&versionNumber,
			&version.Status,
			&version.Algorithm,
			&version.PolicyID,
			&version.Material,
		); err != nil {
			return nil, fmt.Errorf("scan key version: %w", err)
		}
		version.Ref.ClusterID = clusterID
		if versionNumber < 0 || versionNumber > maxKeyVersion {
			return nil, fmt.Errorf("key version exceeds uint32: %d", versionNumber)
		}
		version.Ref.Version = uint32(versionNumber)
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate key versions: %w", err)
	}
	return keyring.NewRing(versions...)
}

// KeyVersion loads one key version.
func (s *SQLiteStore) KeyVersion(ctx context.Context, ref keyring.KeyRef) (keyring.KeyVersion, error) {
	var version keyring.KeyVersion
	err := s.db.QueryRowContext(
		ctx,
		`SELECT status, algorithm, policy_id, material
		 FROM key_versions
		 WHERE cluster_id = ? AND key_id = ? AND version = ?`,
		ref.ClusterID,
		ref.KeyID,
		ref.Version,
	).Scan(&version.Status, &version.Algorithm, &version.PolicyID, &version.Material)
	if errors.Is(err, sql.ErrNoRows) {
		return keyring.KeyVersion{}, keyring.ErrKeyNotFound
	}
	if err != nil {
		return keyring.KeyVersion{}, fmt.Errorf("query key version: %w", err)
	}
	version.Ref = ref
	return version, nil
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

// InsertAuditEvent stores an audit event in SQLite.
func (s *SQLiteStore) InsertAuditEvent(ctx context.Context, event AuditEvent) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO audit_events(audit_id, occurred_at, subject_id, operation, cluster_id, key_id, key_version,
		 decision, policy_id, reason, evidence_hash, remote_addr, error_code)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
		 decision, policy_id, reason, evidence_hash, remote_addr, error_code
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

func rollbackUnlessCommitted(tx *sql.Tx) {
	_ = tx.Rollback()
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
