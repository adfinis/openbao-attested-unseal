package broker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

// AuditEvent is one append-only broker security audit record.
type AuditEvent struct {
	SchemaVersion uint32 `json:"schema_version"`
	AuditID       string `json:"audit_id"`
	Time          string `json:"time"`
	Subject       string `json:"subject"`
	Operation     string `json:"operation"`
	ClusterID     string `json:"cluster_id"`
	KeyID         string `json:"key_id,omitempty"`
	KeyVersion    uint32 `json:"key_version,omitempty"`
	Decision      string `json:"decision"`
	PolicyID      string `json:"policy_id"`
	Reason        string `json:"reason"`
	EvidenceHash  string `json:"evidence_hash,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
}

// FileAuditSink writes JSONL audit events to a local file.
type FileAuditSink struct {
	mu    sync.Mutex
	path  string
	fsync bool
}

// NewFileAuditSink creates the mandatory JSONL file audit sink.
func NewFileAuditSink(path string, fsync bool) *FileAuditSink {
	return &FileAuditSink{path: path, fsync: fsync}
}

// Write appends one audit event.
func (s *FileAuditSink) Write(ctx context.Context, event AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	encoded = append(encoded, '\n')

	// #nosec G304 -- audit file path is operator supplied.
	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit file: %w", err)
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write audit file: %w", err)
	}
	if s.fsync {
		if err := file.Sync(); err != nil {
			return fmt.Errorf("sync audit file: %w", err)
		}
	}
	return nil
}

func newAuditEvent(
	now time.Time,
	subject string,
	operation protocolv1.Operation,
	clusterID string,
	ref keyRefView,
	decision PolicyDecision,
	evidence *protocolv1.EvidenceEnvelope,
	remoteAddress string,
) (AuditEvent, error) {
	auditID, err := randomID("audit")
	if err != nil {
		return AuditEvent{}, err
	}
	errorCode := ""
	if decision.ErrorCode != protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		errorCode = decision.ErrorCode.String()
	}
	return AuditEvent{
		SchemaVersion: 1,
		AuditID:       auditID,
		Time:          now.UTC().Format(time.RFC3339Nano),
		Subject:       subject,
		Operation:     operation.String(),
		ClusterID:     clusterID,
		KeyID:         ref.KeyID,
		KeyVersion:    ref.Version,
		Decision:      decision.State.String(),
		PolicyID:      decision.PolicyID,
		Reason:        decision.Reason,
		EvidenceHash:  evidenceHash(evidence),
		RemoteAddress: remoteAddress,
		ErrorCode:     errorCode,
	}, nil
}

type keyRefView struct {
	KeyID   string
	Version uint32
}
