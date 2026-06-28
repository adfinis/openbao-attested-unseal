package baounsealctl

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/enrollment"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

func TestInitAndStatusJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-audit-file", auditPath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-keyring-profile", "recovery-threshold",
		"-format", "json",
	)
	if initOut.AuditID == "" {
		t.Fatal("init audit ID is empty")
	}
	if initOut.KeyringProfile != "recovery-threshold" {
		t.Fatalf("keyring profile = %q, want recovery-threshold", initOut.KeyringProfile)
	}
	if len(initOut.RecoveryShares) != 5 {
		t.Fatalf("recovery shares = %d, want 5", len(initOut.RecoveryShares))
	}
	// #nosec G304 -- test reads the audit file generated under t.TempDir.
	auditFile, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile audit returned error: %v", err)
	}
	for _, share := range initOut.RecoveryShares {
		if strings.Contains(string(auditFile), share) {
			t.Fatal("audit file contains recovery share")
		}
	}

	var status statusOutput
	runJSON(t, &status, "status", "-state", statePath, "-cluster-id", "prod-eu1", "-format", "json")
	if !status.Ready {
		t.Fatal("status ready = false, want true")
	}
	if status.ActiveKeyID != "prod-eu1/root/v1" {
		t.Fatalf("active key = %q, want prod-eu1/root/v1", status.ActiveKeyID)
	}
}

func TestEnrollmentRequestIssueApplyJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	requestPath := filepath.Join(dir, "request.json")
	grantPath := filepath.Join(dir, "grant.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-format", "json",
	)
	var request enrollRequestOutput
	runJSON(t, &request,
		"enroll", "request",
		"-cluster-id", "prod-eu1",
		"-subject-id", "node-a",
		"-out", requestPath,
		"-operations", "wrap",
		"-format", "json",
	)
	if request.AuditID == "" || request.RequestID == "" {
		t.Fatal("request output is missing IDs")
	}
	var requestFile enrollment.Request
	if err := readJSONFile(requestPath, &requestFile); err != nil {
		t.Fatalf("readJSONFile request returned error: %v", err)
	}
	if got := strings.Join(requestFile.AllowedOperations, ","); got != "wrap" {
		t.Fatalf("request operations = %q, want wrap", got)
	}
	var grant enrollGrantOutput
	runJSON(t, &grant,
		"enroll", "issue",
		"-state", statePath,
		"-request", requestPath,
		"-grant", grantPath,
		"-format", "json",
	)
	if grant.AuditID == "" || grant.GrantID == "" {
		t.Fatal("grant output is missing IDs")
	}
	var applied enrollApplyOutput
	runJSON(t, &applied,
		"enroll", "apply",
		"-state", statePath,
		"-grant", grantPath,
		"-cluster-id", "prod-eu1",
		"-format", "json",
	)
	if applied.SubjectID != "node-a" {
		t.Fatalf("applied subject = %q, want node-a", applied.SubjectID)
	}
	if applied.LocalStatePath == "" {
		t.Fatal("local trust state path is empty")
	}
	info, err := os.Stat(applied.LocalStatePath)
	if err != nil {
		t.Fatalf("Stat local trust state returned error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("local trust state permissions = %04o, want 0600", got)
	}

	store, err := broker.OpenSQLiteStore(context.Background(), statePath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore returned error: %v", err)
	}
	defer func() { _ = store.Close() }()
	if _, err := store.Subject(context.Background(), "prod-eu1", "node-a"); err != nil {
		t.Fatalf("Subject returned error: %v", err)
	}

	err = runCommand(
		"enroll", "apply",
		"-state", statePath,
		"-grant", grantPath,
		"-format", "json",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitCheckFailed) {
		t.Fatalf("replay exit code = %d, want %d", got, cli.ExitCheckFailed)
	}
}

func TestRecoveryEnrollmentRestoresFreshBrokerState(t *testing.T) {
	dir := t.TempDir()
	sourceState := filepath.Join(dir, "source.db")
	targetState := filepath.Join(dir, "target.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	sharesPath := filepath.Join(dir, "shares.json")
	sessionPath := filepath.Join(dir, "session.json")
	targetRequestPath := filepath.Join(dir, "target-request.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", sourceState,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-format", "json",
	)
	if err := writeJSONFile(sharesPath, initOut.RecoveryShares[:3]); err != nil {
		t.Fatalf("writeJSONFile shares returned error: %v", err)
	}
	var begin recoverBeginOutput
	runJSON(t, &begin,
		"recover", "begin",
		"-package", recoveryPath,
		"-shares-file", sharesPath,
		"-session", sessionPath,
		"-format", "json",
	)
	if begin.SessionID == "" {
		t.Fatal("recovery session ID is empty")
	}
	var targetRequest enrollRequestOutput
	runJSON(t, &targetRequest,
		"enroll", "request",
		"-cluster-id", "prod-eu1",
		"-subject-id", "recovered-broker",
		"-out", targetRequestPath,
		"-format", "json",
	)
	var enroll recoverEnrollOutput
	runJSON(t, &enroll,
		"recover", "enroll",
		"-state", targetState,
		"-package", recoveryPath,
		"-shares-file", sharesPath,
		"-session", sessionPath,
		"-request", targetRequestPath,
		"-format", "json",
	)
	if enroll.ClusterID != "prod-eu1" {
		t.Fatalf("recovered cluster = %q, want prod-eu1", enroll.ClusterID)
	}
	if enroll.SubjectID != "recovered-broker" {
		t.Fatalf("recovered subject = %q, want recovered-broker", enroll.SubjectID)
	}
	var status statusOutput
	runJSON(t, &status, "status", "-state", targetState, "-cluster-id", "prod-eu1", "-format", "json")
	if !status.Ready {
		t.Fatal("recovered status ready = false")
	}
	var finish recoverFinishOutput
	runJSON(t, &finish, "recover", "finish", "-session", sessionPath, "-format", "json")
	if finish.SessionID != begin.SessionID {
		t.Fatalf("finish session = %q, want %q", finish.SessionID, begin.SessionID)
	}
	if _, err := os.Stat(sessionPath); !os.IsNotExist(err) {
		t.Fatalf("session file still exists or stat failed: %v", err)
	}
}

func TestUnsafeLocalFilePermissionsRejected(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	requestPath := filepath.Join(dir, "request.json")
	grantPath := filepath.Join(dir, "grant.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-recovery-package", recoveryPath,
		"-format", "json",
	)
	var request enrollRequestOutput
	runJSON(t, &request,
		"enroll", "request",
		"-subject-id", "node-a",
		"-out", requestPath,
		"-format", "json",
	)
	// #nosec G302 -- this deliberately creates unsafe permissions for rejection.
	if err := os.Chmod(requestPath, 0o644); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	err := runCommand(
		"enroll", "issue",
		"-state", statePath,
		"-request", requestPath,
		"-grant", grantPath,
		"-format", "json",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitConfig) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitConfig)
	}
}

func TestEnrollmentApplyRejectsClusterMismatch(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	requestPath := filepath.Join(dir, "request.json")
	grantPath := filepath.Join(dir, "grant.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-format", "json",
	)
	var request enrollRequestOutput
	runJSON(t, &request,
		"enroll", "request",
		"-cluster-id", "prod-eu1",
		"-subject-id", "node-a",
		"-out", requestPath,
		"-format", "json",
	)
	var grant enrollGrantOutput
	runJSON(t, &grant,
		"enroll", "issue",
		"-state", statePath,
		"-request", requestPath,
		"-grant", grantPath,
		"-format", "json",
	)
	err := runCommand(
		"enroll", "apply",
		"-state", statePath,
		"-grant", grantPath,
		"-cluster-id", "stage-eu1",
		"-format", "json",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitCheckFailed) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitCheckFailed)
	}
}

func TestRecoveryBeginDeniedWritesAuditEvent(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	sharesPath := filepath.Join(dir, "shares.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-format", "json",
	)
	if err := writeJSONFile(sharesPath, initOut.RecoveryShares[:2]); err != nil {
		t.Fatalf("writeJSONFile shares returned error: %v", err)
	}
	err := runCommand(
		"recover", "begin",
		"-package", recoveryPath,
		"-shares-file", sharesPath,
		"-audit-file", auditPath,
		"-format", "json",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitCheckFailed) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitCheckFailed)
	}
	// #nosec G304 -- test reads the audit file generated under t.TempDir.
	auditFile, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile audit returned error: %v", err)
	}
	if !strings.Contains(string(auditFile), "POLICY_DECISION_STATE_DENY") {
		t.Fatalf("audit file does not contain deny decision: %s", auditFile)
	}
	for _, share := range initOut.RecoveryShares {
		if strings.Contains(string(auditFile), share) {
			t.Fatal("audit file contains recovery share")
		}
	}
}

func TestRecoveryEnrollRejectsTargetClusterMismatchAndAudits(t *testing.T) {
	dir := t.TempDir()
	sourceState := filepath.Join(dir, "source.db")
	targetState := filepath.Join(dir, "target.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	sharesPath := filepath.Join(dir, "shares.json")
	sessionPath := filepath.Join(dir, "session.json")
	targetRequestPath := filepath.Join(dir, "target-request.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", sourceState,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-format", "json",
	)
	if err := writeJSONFile(sharesPath, initOut.RecoveryShares[:3]); err != nil {
		t.Fatalf("writeJSONFile shares returned error: %v", err)
	}
	var begin recoverBeginOutput
	runJSON(t, &begin,
		"recover", "begin",
		"-package", recoveryPath,
		"-shares-file", sharesPath,
		"-session", sessionPath,
		"-format", "json",
	)
	var targetRequest enrollRequestOutput
	runJSON(t, &targetRequest,
		"enroll", "request",
		"-cluster-id", "stage-eu1",
		"-subject-id", "recovered-broker",
		"-out", targetRequestPath,
		"-format", "json",
	)
	err := runCommand(
		"recover", "enroll",
		"-state", targetState,
		"-package", recoveryPath,
		"-shares-file", sharesPath,
		"-session", sessionPath,
		"-request", targetRequestPath,
		"-audit-file", auditPath,
		"-format", "json",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitCheckFailed) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitCheckFailed)
	}
	// #nosec G304 -- test reads the audit file generated under t.TempDir.
	auditFile, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile audit returned error: %v", err)
	}
	if !strings.Contains(string(auditFile), "recovery target cluster mismatch") {
		t.Fatalf("audit file does not contain mismatch reason: %s", auditFile)
	}
}

func runJSON(t *testing.T, out any, args ...string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(version.Info{Version: "test"}, args, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Execute(%v) returned error: %v\nstderr: %s", args, err, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), out); err != nil {
		t.Fatalf("Unmarshal output returned error: %v\nstdout: %s", err, stdout.String())
	}
}

func runCommand(args ...string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	return Execute(version.Info{Version: "test"}, args, &stdout, &stderr)
}
