package baounsealctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/enrollment"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

const (
	testActiveKeyV1   = "prod-eu1/root/v1"
	testDecisionAllow = "allow"
	testK8sNodeName   = "kind-worker"
	testStatusFresh   = "fresh"
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
	if status.ActiveKeyID != testActiveKeyV1 {
		t.Fatalf("active key = %q, want %s", status.ActiveKeyID, testActiveKeyV1)
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

func TestTPMProvisionAndStatusWithSWTPM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("swtpm integration is not supported on Windows")
	}
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm is not installed")
	}
	socketPath, stop := startSWTPMForCTL(t)
	defer stop()

	dir := t.TempDir()
	brokerState := filepath.Join(dir, "broker.db")
	localTPMState := filepath.Join(dir, "local-tpm-state")
	recoveryPath := filepath.Join(dir, "recovery.json")
	sharesPath := filepath.Join(dir, "shares.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", brokerState,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-format", "json",
	)
	if err := writeJSONFile(sharesPath, initOut.RecoveryShares[:3]); err != nil {
		t.Fatalf("writeJSONFile shares returned error: %v", err)
	}

	var provision tpmProvisionOutput
	runJSON(t, &provision,
		"tpm", "provision",
		"-state-path", localTPMState,
		"-package", recoveryPath,
		"-shares-file", sharesPath,
		"-tpm-device", socketPath,
		"-format", "json",
	)
	if provision.KeyID != "prod-eu1/root/v1" {
		t.Fatalf("provision key = %q, want prod-eu1/root/v1", provision.KeyID)
	}
	if !containsString(provision.Warnings, "local TPM revocation requires key rotation") {
		t.Fatalf("provision warnings = %v", provision.Warnings)
	}
	if provision.SealConfig == "" {
		t.Fatal("seal config is empty")
	}

	var status tpmStatusOutput
	runJSON(t, &status,
		"tpm", "status",
		"-state-path", localTPMState,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-key-version", "1",
		"-format", "json",
	)
	if !status.Ready {
		t.Fatalf("TPM status ready = false, errors = %v", status.Errors)
	}
	if status.PolicyMode != "tpm-only" {
		t.Fatalf("TPM status policy = %q, want tpm-only", status.PolicyMode)
	}
	if !containsString(status.Warnings, "local TPM revocation requires key rotation") {
		t.Fatalf("status warnings = %v", status.Warnings)
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

func TestRotationStartStatusActivateJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-format", "json",
	)

	var started rotateOutput
	runJSON(t, &started,
		"rotate", "start",
		"-state", statePath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-policy-id", "rotation",
		"-format", "json",
	)
	if started.AuditID == "" || started.OperationID == "" {
		t.Fatal("rotation start output is missing IDs")
	}
	if started.FromVersion != 1 || started.ToVersion != 2 || started.Status != string(broker.RotationStatusStarted) {
		t.Fatalf("started rotation = %#v, want v1 -> v2 started", started)
	}

	var rotationStatus rotateOutput
	runJSON(t, &rotationStatus,
		"rotate", "status",
		"-state", statePath,
		"-operation-id", started.OperationID,
		"-format", "json",
	)
	if rotationStatus.Status != string(broker.RotationStatusStarted) {
		t.Fatalf("rotation status = %q, want started", rotationStatus.Status)
	}

	var statusBefore statusOutput
	runJSON(t, &statusBefore, "status", "-state", statePath, "-cluster-id", "prod-eu1", "-format", "json")
	if statusBefore.ActiveKeyID != testActiveKeyV1 {
		t.Fatalf("active key before activation = %q, want %s", statusBefore.ActiveKeyID, testActiveKeyV1)
	}

	var activated rotateOutput
	runJSON(t, &activated,
		"rotate", "activate",
		"-state", statePath,
		"-operation-id", started.OperationID,
		"-format", "json",
	)
	if activated.Status != string(broker.RotationStatusActivated) {
		t.Fatalf("activated status = %q, want activated", activated.Status)
	}

	var statusAfter statusOutput
	runJSON(t, &statusAfter, "status", "-state", statePath, "-cluster-id", "prod-eu1", "-format", "json")
	if statusAfter.ActiveKeyID != "prod-eu1/root/v2" {
		t.Fatalf("active key after activation = %q, want prod-eu1/root/v2", statusAfter.ActiveKeyID)
	}

	store, err := broker.OpenSQLiteStore(context.Background(), statePath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore returned error: %v", err)
	}
	defer func() { _ = store.Close() }()
	assertCLIKeyStatus(t, store, "prod-eu1", "root", 1, keyring.StatusDecryptOnly)
	assertCLIKeyStatus(t, store, "prod-eu1", "root", 2, keyring.StatusActive)
}

func TestRotateOpenBAORootJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	var initOut initOutput
	runJSON(t, &initOut, "init", "-state", statePath, "-recovery-package", recoveryPath, "-format", "json")
	var started rotateOutput
	runJSON(t, &started, "rotate", "start", "-state", statePath, "-format", "json")
	var activated rotateOutput
	runJSON(t, &activated,
		"rotate", "activate",
		"-state", statePath,
		"-operation-id", started.OperationID,
		"-format", "json",
	)

	server := startOpenBAORotationTestServer(t)

	t.Setenv("BAO_TOKEN", "test-token")
	var out rotateOpenBAORootOutput
	runJSON(t, &out,
		"rotate", "openbao-root",
		"-state", statePath,
		"-audit-file", auditPath,
		"-operation-id", activated.OperationID,
		"-addr", server.URL,
		"-format", "json",
	)
	if server.RotateRootCalls != 1 {
		t.Fatalf("OpenBao root rotation calls = %d, want 1", server.RotateRootCalls)
	}
	assertOpenBAORootOutput(t, out, activated.OperationID, server.URL)

	var restartOut rotateVerifyRestartOutput
	runJSON(t, &restartOut,
		"rotate", "verify-restart",
		"-state", statePath,
		"-audit-file", auditPath,
		"-operation-id", activated.OperationID,
		"-addr", server.URL,
		"-format", "json",
	)
	if server.SealStatusCalls != 1 {
		t.Fatalf("OpenBao seal-status calls = %d, want 1", server.SealStatusCalls)
	}
	assertRestartVerificationOutput(t, restartOut)

	var rotationStatus rotateOutput
	runJSON(t, &rotationStatus,
		"rotate", "status",
		"-state", statePath,
		"-operation-id", activated.OperationID,
		"-format", "json",
	)
	assertVerificationOutput(t, rotationStatus.Verifications, broker.RotationVerificationOpenBAORoot, true)
	assertVerificationOutput(t, rotationStatus.Verifications, broker.RotationVerificationRestart, true)
	assertVerificationOutput(t, rotationStatus.Verifications, broker.RotationVerificationKeyVersion, false)
	assertRotationAuditFile(t, auditPath)
}

func TestRotateVerifyRestartRequiresOpenBAORootVerification(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")

	var initOut initOutput
	runJSON(t, &initOut, "init", "-state", statePath, "-recovery-package", recoveryPath, "-format", "json")
	var started rotateOutput
	runJSON(t, &started, "rotate", "start", "-state", statePath, "-format", "json")
	var activated rotateOutput
	runJSON(t, &activated,
		"rotate", "activate",
		"-state", statePath,
		"-operation-id", started.OperationID,
		"-format", "json",
	)

	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"attested","initialized":true,"sealed":false}`))
	}))
	defer server.Close()

	err := runCommand(
		"rotate", "verify-restart",
		"-state", statePath,
		"-operation-id", activated.OperationID,
		"-addr", server.URL,
	)
	if err == nil {
		t.Fatal("verify-restart returned nil error, want missing openbao-root verification error")
	}
	var exitErr cli.ExitErrorWithCode
	if !errors.As(err, &exitErr) || exitErr.Code != cli.ExitCheckFailed {
		t.Fatalf("verify-restart exit error = %v, want ExitCheckFailed", err)
	}
	if seen != 0 {
		t.Fatalf("OpenBao server calls = %d, want 0", seen)
	}
}

func TestRotateOpenBAORootRequiresActivatedOperation(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")

	var initOut initOutput
	runJSON(t, &initOut, "init", "-state", statePath, "-recovery-package", recoveryPath, "-format", "json")
	var started rotateOutput
	runJSON(t, &started, "rotate", "start", "-state", statePath, "-format", "json")

	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	t.Setenv("BAO_TOKEN", "test-token")
	err := runCommand(
		"rotate", "openbao-root",
		"-state", statePath,
		"-operation-id", started.OperationID,
		"-addr", server.URL,
	)
	if err == nil {
		t.Fatal("openbao-root returned nil error, want activation error")
	}
	var exitErr cli.ExitErrorWithCode
	if !errors.As(err, &exitErr) || exitErr.Code != cli.ExitCheckFailed {
		t.Fatalf("openbao-root exit error = %v, want ExitCheckFailed", err)
	}
	if seen != 0 {
		t.Fatalf("OpenBao server calls = %d, want 0", seen)
	}
}

func TestRotateOpenBAORootRequiresBAOToken(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")

	var initOut initOutput
	runJSON(t, &initOut, "init", "-state", statePath, "-recovery-package", recoveryPath, "-format", "json")
	var started rotateOutput
	runJSON(t, &started, "rotate", "start", "-state", statePath, "-format", "json")
	var activated rotateOutput
	runJSON(t, &activated,
		"rotate", "activate",
		"-state", statePath,
		"-operation-id", started.OperationID,
		"-format", "json",
	)

	t.Setenv("BAO_TOKEN", "")
	err := runCommand(
		"rotate", "openbao-root",
		"-state", statePath,
		"-operation-id", activated.OperationID,
		"-addr", "http://127.0.0.1:8200",
	)
	if err == nil {
		t.Fatal("openbao-root returned nil error, want BAO_TOKEN error")
	}
	var exitErr cli.ExitErrorWithCode
	if !errors.As(err, &exitErr) || exitErr.Code != cli.ExitConfig {
		t.Fatalf("openbao-root exit error = %v, want ExitConfig", err)
	}
}

func TestRevokeSubjectJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")

	var initOut initOutput
	runJSON(t, &initOut,
		"init",
		"-state", statePath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-format", "json",
	)
	store, err := broker.OpenSQLiteStore(context.Background(), statePath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore returned error: %v", err)
	}
	if err := store.InsertSubject(context.Background(), "prod-eu1", "node-a", time.Now()); err != nil {
		t.Fatalf("InsertSubject returned error: %v", err)
	}

	var revoked revokeSubjectOutput
	runJSON(t, &revoked,
		"revoke", "subject",
		"-state", statePath,
		"-cluster-id", "prod-eu1",
		"-subject-id", "node-a",
		"-format", "json",
	)
	if revoked.AuditID == "" || !revoked.Revoked || revoked.Mode != revocationModeBroker {
		t.Fatalf("revoked output = %#v, want broker revocation with audit ID", revoked)
	}
	if _, err := store.Subject(context.Background(), "prod-eu1", "node-a"); !errors.Is(err, broker.ErrSubjectRevoked) {
		t.Fatalf("Subject error = %v, want ErrSubjectRevoked", err)
	}
	_ = store.Close()

	var status revokeStatusOutput
	runJSON(t, &status,
		"revoke", "status",
		"-state", statePath,
		"-cluster-id", "prod-eu1",
		"-subject-id", "node-a",
		"-format", "json",
	)
	if !status.Revoked {
		t.Fatalf("revoke status = %#v, want revoked", status)
	}
}

func TestLocalTPMRevokeRequiresRotationPlanAndWarns(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "broker.db")
	recoveryPath := filepath.Join(dir, "recovery.json")

	var initOut initOutput
	runJSON(t, &initOut, "init", "-state", statePath, "-recovery-package", recoveryPath, "-format", "json")
	store, err := broker.OpenSQLiteStore(context.Background(), statePath)
	if err != nil {
		t.Fatalf("OpenSQLiteStore returned error: %v", err)
	}
	if err := store.InsertSubject(context.Background(), "prod-eu1", "node-tpm", time.Now()); err != nil {
		t.Fatalf("InsertSubject returned error: %v", err)
	}
	_ = store.Close()

	err = runCommand(
		"revoke", "subject",
		"-state", statePath,
		"-subject-id", "node-tpm",
		"-mode", "local-tpm",
		"-format", "json",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("local-tpm revoke without plan exit code = %d, want %d", got, cli.ExitUsage)
	}

	var revoked revokeSubjectOutput
	runJSON(t, &revoked,
		"revoke", "subject",
		"-state", statePath,
		"-subject-id", "node-tpm",
		"-mode", "local-tpm",
		"-rotation-plan", "rot_planned",
		"-format", "json",
	)
	if revoked.RotationPlan != "rot_planned" || !containsString(
		revoked.Warnings,
		"local TPM revocation does not remove TPM-sealed key material",
	) {
		t.Fatalf("local-tpm revoke output = %#v, want rotation plan warning", revoked)
	}
}

func TestK8sPublishNodeJSON(t *testing.T) {
	address, cache := startAdminBrokerTestServer(t)

	var out k8sPublishNodeOutput
	runJSON(t, &out,
		"k8s", "publish-node",
		"-addr", address,
		"-plaintext",
		"-cluster-id", "prod-eu1",
		"-node-name", testK8sNodeName,
		"-node-uid", "node-uid",
		"-ttl", "1m",
		"-format", "json",
	)
	if out.Decision != testDecisionAllow || out.Status != testStatusFresh {
		t.Fatalf("publish output = %#v, want allow/fresh", out)
	}
	if out.ProviderID != kubernetesProviderFakeLocal {
		t.Fatalf("provider_id = %q, want %q", out.ProviderID, kubernetesProviderFakeLocal)
	}
	if out.EvidenceHash == "" || out.CollectedAt == "" || out.ExpiresAt == "" {
		t.Fatalf("publish output is missing evidence metadata: %#v", out)
	}

	evidence, err := cache.NodeEvidence(context.Background(), "prod-eu1", testK8sNodeName)
	if err != nil {
		t.Fatalf("NodeEvidence returned error: %v", err)
	}
	if evidence.NodeUID != "node-uid" || evidence.Provider != kubernetesProviderFakeLocal {
		t.Fatalf("cached evidence = %#v, want node-uid fake-local", evidence)
	}
}

func TestK8sEvidenceListAndInspectJSON(t *testing.T) {
	address, _ := startAdminBrokerTestServer(t)

	var published k8sPublishNodeOutput
	runJSON(t, &published,
		"k8s", "publish-node",
		"-addr", address,
		"-plaintext",
		"-cluster-id", "prod-eu1",
		"-node-name", testK8sNodeName,
		"-node-uid", "node-uid",
		"-ttl", "1m",
		"-format", "json",
	)

	var list k8sEvidenceListOutput
	runJSON(t, &list,
		"k8s", "evidence", "list",
		"-addr", address,
		"-plaintext",
		"-cluster-id", "prod-eu1",
		"-format", "json",
	)
	if list.Decision != testDecisionAllow || list.Count != 1 {
		t.Fatalf("list output = %#v, want allow with one record", list)
	}
	if list.Evidence[0].NodeName != testK8sNodeName ||
		list.Evidence[0].NodeUID != "node-uid" ||
		list.Evidence[0].EvidenceHash != published.EvidenceHash {
		t.Fatalf("list evidence = %#v, want published record", list.Evidence[0])
	}

	var inspect k8sEvidenceInspectOutput
	runJSON(t, &inspect,
		"k8s", "evidence", "inspect",
		"-addr", address,
		"-plaintext",
		"-cluster-id", "prod-eu1",
		"-node-name", testK8sNodeName,
		"-format", "json",
	)
	if inspect.Decision != testDecisionAllow || inspect.Evidence.NodeName != testK8sNodeName {
		t.Fatalf("inspect output = %#v, want allow kind-worker", inspect)
	}
}

func TestK8sEvidenceListReportsStaleEvidence(t *testing.T) {
	address, cache := startAdminBrokerTestServer(t)
	now := time.Now().UTC()
	err := cache.PutNodeEvidence(context.Background(), broker.NodeEvidence{
		ClusterID:    "prod-eu1",
		NodeName:     testK8sNodeName,
		NodeUID:      "node-uid",
		Provider:     kubernetesProviderFakeLocal,
		EvidenceHash: "stale-evidence-hash",
		CollectedAt:  now.Add(-2 * time.Minute),
		ExpiresAt:    now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("PutNodeEvidence returned error: %v", err)
	}

	var list k8sEvidenceListOutput
	runJSON(t, &list,
		"k8s", "evidence", "list",
		"-addr", address,
		"-plaintext",
		"-cluster-id", "prod-eu1",
		"-node-name", testK8sNodeName,
		"-format", "json",
	)
	if list.Count != 1 || list.Evidence[0].Status != "stale" {
		t.Fatalf("list output = %#v, want one stale record", list)
	}
}

func TestK8sEvidenceListMissingEvidenceFailsCheck(t *testing.T) {
	address, _ := startAdminBrokerTestServer(t)

	err := runCommand(
		"k8s", "evidence", "list",
		"-addr", address,
		"-plaintext",
		"-cluster-id", "prod-eu1",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitCheckFailed) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitCheckFailed)
	}
}

func TestK8sEvidenceInspectRequiresNodeName(t *testing.T) {
	err := runCommand(
		"k8s", "evidence", "inspect",
		"-addr", "127.0.0.1:8443",
		"-plaintext",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitUsage)
	}
}

func TestK8sPublishNodeRequiresNodeName(t *testing.T) {
	err := runCommand(
		"k8s", "publish-node",
		"-addr", "127.0.0.1:8443",
		"-plaintext",
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitUsage)
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

func startAdminBrokerTestServer(t *testing.T) (string, *broker.MemoryNodeEvidenceCache) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	config := broker.Config{
		AllowPlaintextForTests: true,
		PolicyID:               "development",
		Kubernetes: broker.KubernetesConfig{
			AllowFakeNodeEvidencePublish: true,
		},
	}
	cache := broker.NewMemoryNodeEvidenceCache()
	service := broker.NewService(config, nil, nil, nil)
	server, err := broker.NewGRPCServer(config, service, cache)
	if err != nil {
		t.Fatalf("NewGRPCServer returned error: %v", err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		select {
		case <-errCh:
		default:
		}
	})
	return listener.Addr().String(), cache
}

type openBAORotationTestServer struct {
	*httptest.Server
	RotateRootCalls int
	SealStatusCalls int
}

func startOpenBAORotationTestServer(t *testing.T) *openBAORotationTestServer {
	t.Helper()
	fixture := &openBAORotationTestServer{}
	fixture.Server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(fixture.Close)
	return fixture
}

func (s *openBAORotationTestServer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/sys/rotate/root":
		s.handleRotateRoot(w, r)
	case "/v1/sys/seal-status":
		s.handleSealStatus(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *openBAORotationTestServer) handleRotateRoot(w http.ResponseWriter, r *http.Request) {
	s.RotateRootCalls++
	if r.Method != http.MethodPost {
		http.Error(w, "method must be POST", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Vault-Request") != "true" {
		http.Error(w, "missing X-Vault-Request", http.StatusBadRequest)
		return
	}
	if r.Header.Get("X-Vault-Token") != "test-token" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *openBAORotationTestServer) handleSealStatus(w http.ResponseWriter, r *http.Request) {
	s.SealStatusCalls++
	if r.Method != http.MethodGet {
		http.Error(w, "method must be GET", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Vault-Token") != "" {
		http.Error(w, "seal-status must be unauthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"type":"attested","initialized":true,"sealed":false}`))
}

func assertOpenBAORootOutput(
	t *testing.T,
	out rotateOpenBAORootOutput,
	operationID string,
	address string,
) {
	t.Helper()
	if out.AuditID == "" || out.OperationID != operationID || out.HTTPStatus != http.StatusNoContent {
		t.Fatalf("openbao-root output = %#v", out)
	}
	if !out.Verification.Verified || out.Verification.Name != string(broker.RotationVerificationOpenBAORoot) {
		t.Fatalf("openbao-root verification = %#v, want verified openbao-root", out.Verification)
	}
	if out.Endpoint != address+"/v1/sys/rotate/root" {
		t.Fatalf("endpoint = %q, want %s", out.Endpoint, address+"/v1/sys/rotate/root")
	}
}

func assertRestartVerificationOutput(t *testing.T, out rotateVerifyRestartOutput) {
	t.Helper()
	if !out.Verification.Verified ||
		out.Verification.Name != string(broker.RotationVerificationRestart) ||
		!out.OpenBaoInitialized ||
		out.OpenBaoSealed {
		t.Fatalf("restart verification output = %#v, want verified unsealed restart", out)
	}
}

func assertRotationAuditFile(t *testing.T, auditPath string) {
	t.Helper()
	// #nosec G304 -- test reads the audit file generated under t.TempDir.
	auditFile, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile audit returned error: %v", err)
	}
	if strings.Contains(string(auditFile), "test-token") {
		t.Fatal("audit file contains BAO_TOKEN")
	}
	for _, reason := range []string{
		"openbao root key rotation completed",
		"openbao restart verification completed",
	} {
		if !strings.Contains(string(auditFile), reason) {
			t.Fatalf("audit file does not contain %q: %s", reason, auditFile)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertVerificationOutput(
	t *testing.T,
	verifications []rotationVerificationOutput,
	name broker.RotationVerificationName,
	verified bool,
) {
	t.Helper()
	for _, verification := range verifications {
		if verification.Name != string(name) {
			continue
		}
		if verification.Verified != verified {
			t.Fatalf("verification %s verified = %t, want %t", name, verification.Verified, verified)
		}
		return
	}
	t.Fatalf("verification %s not found in %#v", name, verifications)
}

func assertCLIKeyStatus(
	t *testing.T,
	store *broker.SQLiteStore,
	clusterID string,
	keyID string,
	keyVersion uint32,
	status keyring.Status,
) {
	t.Helper()
	got, err := store.KeyVersion(context.Background(), keyring.KeyRef{
		ClusterID: clusterID,
		KeyID:     keyID,
		Version:   keyVersion,
	})
	if err != nil {
		t.Fatalf("KeyVersion returned error: %v", err)
	}
	if got.Status != status {
		t.Fatalf("key status = %q, want %q", got.Status, status)
	}
}

func startSWTPMForCTL(t *testing.T) (string, func()) {
	t.Helper()
	baseDir, err := os.MkdirTemp("/tmp", "bao-swtpm-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(baseDir)
	})
	stateDir := filepath.Join(baseDir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	socketPath := filepath.Join(baseDir, "swtpm.sock")
	ctrlPath := filepath.Join(baseDir, "swtpm.ctrl")
	logPath := filepath.Join(baseDir, "swtpm.log")
	//nolint:gosec // Test harness starts the local swtpm binary with controlled temporary paths.
	cmd := exec.Command(
		"swtpm",
		"socket",
		"--tpm2",
		"--tpmstate", "dir="+stateDir,
		"--ctrl", "type=unixio,path="+ctrlPath,
		"--server", "type=unixio,path="+socketPath,
		"--flags", "not-need-init,startup-clear",
		"--log", "file="+logPath+",level=1",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("swtpm socket was not created; log path: %s", logPath)
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop := func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}
	return socketPath, stop
}
