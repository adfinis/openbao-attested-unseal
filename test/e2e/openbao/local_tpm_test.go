//go:build e2e

package openbao

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	defaultOpenBaoImage = "openbao/openbao:2.6.0-beta20260622"
	defaultAlpineImage  = "alpine:3.20"
	baoAddr             = "http://127.0.0.1:8200"
)

type initOutput struct {
	RecoveryShares []string `json:"recovery_shares"`
	RootToken      string   `json:"root_token"`
}

type baoStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Version     string `json:"version"`
	StorageType string `json:"storage_type"`
}

type kmsTraceEvent struct {
	Operation       string `json:"operation"`
	Mode            string `json:"mode"`
	KeyID           string `json:"key_id"`
	PlaintextBytes  int    `json:"plaintext_bytes"`
	CiphertextBytes int    `json:"ciphertext_bytes"`
	AADBytes        int    `json:"aad_bytes"`
}

type ctlRotateOutput struct {
	OperationID string `json:"operation_id"`
	HTTPStatus  int    `json:"http_status"`
}

func TestLocalTPMAutoUnsealWithOpenBaoBeta(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker bind mounts in this E2E are not supported on Windows")
	}
	requireDocker(t)

	repoRoot := findRepoRoot(t)
	openbaoImage := envDefault("OPENBAO_E2E_IMAGE", defaultOpenBaoImage)
	alpineImage := envDefault("OPENBAO_E2E_ALPINE_IMAGE", defaultAlpineImage)
	pullImageIfMissing(t, openbaoImage)
	pullImageIfMissing(t, alpineImage)

	dockerArch := dockerServerArch(t)
	goarch := dockerGOARCH(t, dockerArch)
	workDir := newE2EWorkDir(t)
	binDir := filepath.Join(workDir, "bin")
	pluginDir := filepath.Join(workDir, "plugins")
	configDir := filepath.Join(workDir, "config")
	mkdirAll(t, binDir, 0o700)
	mkdirAll(t, pluginDir, 0o700)
	mkdirAll(t, configDir, 0o700)

	hostCtl := filepath.Join(binDir, "bao-unsealctl-host")
	linuxCtl := filepath.Join(binDir, "bao-unsealctl-linux")
	pluginPath := filepath.Join(pluginDir, "bao-kms-unseal")
	buildBinary(t, repoRoot, hostCtl, "", "", "./cmd/bao-unsealctl")
	buildBinary(t, repoRoot, linuxCtl, "linux", goarch, "./cmd/bao-unsealctl")
	buildBinary(t, repoRoot, pluginPath, "linux", goarch, "./cmd/bao-kms-unseal")
	chmod(t, linuxCtl, 0o755)
	chmod(t, pluginPath, 0o755)

	runID := fmt.Sprintf("openbao-au-e2e-%d-%d", time.Now().UnixNano(), os.Getpid())
	tpmVolume := runID + "-tpm"
	stateVolume := runID + "-state"
	baoVolume := runID + "-bao"
	traceVolume := runID + "-trace"
	swtpmName := runID + "-swtpm"
	baoName := runID + "-bao"
	keep := os.Getenv("OPENBAO_E2E_KEEP") == "1"
	if !keep {
		t.Cleanup(func() {
			dockerIgnore(t, "rm", "-f", baoName, swtpmName)
			dockerIgnore(t, "volume", "rm", tpmVolume, stateVolume, baoVolume, traceVolume)
		})
		t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	} else {
		t.Logf("OPENBAO_E2E_KEEP=1; keeping work dir %s and Docker resources with prefix %s", workDir, runID)
	}

	docker(t, false, "volume", "create", tpmVolume)
	docker(t, false, "volume", "create", stateVolume)
	docker(t, false, "volume", "create", baoVolume)
	docker(t, false, "volume", "create", traceVolume)
	startSWTPM(t, alpineImage, swtpmName, tpmVolume)
	waitForSWTPMSocket(t, alpineImage, tpmVolume)

	recoveryPath := filepath.Join(workDir, "recovery.json")
	sharesPath := filepath.Join(workDir, "shares.json")
	brokerPath := filepath.Join(workDir, "broker.db")
	initJSON := run(t, true, hostCtl,
		"init",
		"-state", brokerPath,
		"-recovery-package", recoveryPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-shares", "5",
		"-threshold", "3",
		"-format", "json",
	)
	writeThresholdShares(t, initJSON, sharesPath)
	chmod(t, recoveryPath, 0o600)
	chmod(t, sharesPath, 0o600)

	docker(t, true,
		"run", "--rm",
		"-v", tpmVolume+":/tpm",
		"-v", stateVolume+":/state",
		"-v", linuxCtl+":/usr/local/bin/bao-unsealctl:ro",
		"-v", recoveryPath+":/recovery.json:ro",
		"-v", sharesPath+":/shares.json:ro",
		alpineImage,
		"/usr/local/bin/bao-unsealctl",
		"tpm", "provision",
		"-state-path", "/state",
		"-package", "/recovery.json",
		"-shares-file", "/shares.json",
		"-cluster-id", "prod-eu1",
		"-tpm-device", "/tpm/swtpm.sock",
		"-format", "json",
	)
	docker(t, false,
		"run", "--rm",
		"-v", stateVolume+":/state",
		"-v", baoVolume+":/bao",
		"-v", traceVolume+":/trace",
		alpineImage,
		"sh", "-lc", "chown -R 100:1000 /state /bao /trace && chmod -R go-rwx /state /trace || true",
	)

	writeOpenBaoConfig(t, filepath.Join(configDir, "openbao.hcl"), sha256Hex(t, pluginPath))

	startOpenBao(t, openbaoImage, baoName, tpmVolume, stateVolume, baoVolume, traceVolume, pluginDir, configDir)
	before := waitForStatus(t, baoName, false, true, 30*time.Second)
	assertStatus(t, before, false, true)

	openBaoInitJSON := docker(t, true,
		"exec",
		"-e", "BAO_ADDR="+baoAddr,
		baoName,
		"bao", "operator", "init",
		"-recovery-shares=1",
		"-recovery-threshold=1",
		"-format=json",
	)
	openBaoInit := parseOpenBaoInit(t, openBaoInitJSON)
	afterInit := waitForStatus(t, baoName, true, false, 30*time.Second)
	assertStatus(t, afterInit, true, false)

	beforeRotateEvents := waitForTraceOperationCount(t, alpineImage, traceVolume, "encrypt", 1, 10*time.Second)
	beforeRotateEncryptCount := countTraceOperation(beforeRotateEvents, "encrypt")
	operation := startActivatedRotation(t, hostCtl, brokerPath)
	openBAORootJSON := docker(t, true,
		"run", "--rm",
		"--network", "container:"+baoName,
		"-e", "BAO_ADDR="+baoAddr,
		"-e", "BAO_TOKEN="+openBaoInit.RootToken,
		"-v", linuxCtl+":/usr/local/bin/bao-unsealctl:ro",
		"-v", brokerPath+":/broker.db",
		alpineImage,
		"/usr/local/bin/bao-unsealctl",
		"rotate", "openbao-root",
		"-state", "/broker.db",
		"-operation-id", operation.OperationID,
		"-addr", baoAddr,
		"-format", "json",
	)
	assertOpenBAORootRotation(t, openBAORootJSON)
	afterRotateEvents := waitForTraceOperationCount(
		t,
		alpineImage,
		traceVolume,
		"encrypt",
		beforeRotateEncryptCount+1,
		10*time.Second,
	)
	assertLastTraceKeyID(t, afterRotateEvents, "encrypt", "prod-eu1/root/v1")
	decryptCountBeforeRestart := countTraceOperation(afterRotateEvents, "decrypt")

	docker(t, false, "rm", "-f", baoName)
	startOpenBao(t, openbaoImage, baoName, tpmVolume, stateVolume, baoVolume, traceVolume, pluginDir, configDir)
	afterRestart := waitForStatus(t, baoName, true, false, 90*time.Second)
	assertStatus(t, afterRestart, true, false)
	afterRestartEvents := waitForTraceOperationCount(
		t,
		alpineImage,
		traceVolume,
		"decrypt",
		decryptCountBeforeRestart+1,
		10*time.Second,
	)
	assertLastTraceKeyID(t, afterRestartEvents, "decrypt", "prod-eu1/root/v1")
}

func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	//nolint:gosec // E2E harness intentionally invokes the local Docker CLI.
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("docker is not available: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root")
		}
		dir = parent
	}
}

func envDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func pullImageIfMissing(t *testing.T, image string) {
	t.Helper()
	if _, err := dockerOutput("image", "inspect", image); err == nil {
		return
	}
	docker(t, false, "pull", image)
}

func dockerServerArch(t *testing.T) string {
	t.Helper()
	output := docker(t, false, "version", "--format", "{{.Server.Arch}}")
	return strings.TrimSpace(output)
}

func dockerGOARCH(t *testing.T, dockerArch string) string {
	t.Helper()
	switch dockerArch {
	case "amd64", "arm64":
		return dockerArch
	default:
		t.Fatalf("unsupported Docker server architecture %q", dockerArch)
		return ""
	}
}

func newE2EWorkDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "openbao-attested-unseal-e2e-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	return dir
}

func mkdirAll(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatalf("MkdirAll %s returned error: %v", path, err)
	}
}

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod %s returned error: %v", path, err)
	}
}

func buildBinary(t *testing.T, repoRoot string, output string, goos string, goarch string, pkg string) {
	t.Helper()
	args := []string{"build", "-trimpath", "-buildvcs=false", "-o", output, pkg}
	if pkg == "./cmd/bao-kms-unseal" {
		args = []string{"build", "-trimpath", "-buildvcs=false", "-tags=e2e", "-o", output, pkg}
	}
	env := append([]string{}, os.Environ()...)
	env = append(env, "CGO_ENABLED=0")
	if goos != "" {
		env = append(env, "GOOS="+goos, "GOARCH="+goarch)
	}
	runWithEnv(t, false, repoRoot, env, "go", args...)
}

func startSWTPM(t *testing.T, alpineImage string, name string, tpmVolume string) {
	t.Helper()
	docker(t, false,
		"run", "-d",
		"--name", name,
		"-v", tpmVolume+":/tpm",
		alpineImage,
		"sh", "-lc",
		"apk add --no-cache swtpm >/dev/null && "+
			"mkdir -p /tpm/state && "+
			"swtpm socket --tpm2 "+
			"--server type=unixio,path=/tpm/swtpm.sock "+
			"--ctrl type=unixio,path=/tpm/swtpm.ctrl "+
			"--tpmstate dir=/tpm/state "+
			"--flags startup-clear",
	)
}

func waitForSWTPMSocket(t *testing.T, alpineImage string, tpmVolume string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastOutput string
	for time.Now().Before(deadline) {
		output, err := dockerOutput(
			"run", "--rm",
			"-v", tpmVolume+":/tpm",
			alpineImage,
			"sh", "-lc", "test -S /tpm/swtpm.sock && chmod 0777 /tpm/swtpm.sock /tpm/swtpm.ctrl",
		)
		if err == nil {
			return
		}
		lastOutput = output
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("swtpm socket did not become ready: %s", lastOutput)
}

func writeThresholdShares(t *testing.T, initJSON string, sharesPath string) {
	t.Helper()
	var init initOutput
	if err := json.Unmarshal([]byte(initJSON), &init); err != nil {
		t.Fatalf("parse init JSON returned error: %v", err)
	}
	if len(init.RecoveryShares) < 3 {
		t.Fatalf("init returned %d recovery shares, want at least 3", len(init.RecoveryShares))
	}
	body, err := json.Marshal(init.RecoveryShares[:3])
	if err != nil {
		t.Fatalf("marshal threshold shares returned error: %v", err)
	}
	if err := os.WriteFile(sharesPath, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile shares returned error: %v", err)
	}
}

func parseOpenBaoInit(t *testing.T, initJSON string) initOutput {
	t.Helper()
	var init initOutput
	if err := json.Unmarshal([]byte(initJSON), &init); err != nil {
		t.Fatalf("parse OpenBao init JSON returned error: %v", err)
	}
	if strings.TrimSpace(init.RootToken) == "" {
		t.Fatal("OpenBao init did not return a root token")
	}
	return init
}

func startActivatedRotation(t *testing.T, hostCtl string, brokerPath string) ctlRotateOutput {
	t.Helper()
	startJSON := run(t, false, hostCtl,
		"rotate", "start",
		"-state", brokerPath,
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-policy-id", "rotation",
		"-format", "json",
	)
	var started ctlRotateOutput
	if err := json.Unmarshal([]byte(startJSON), &started); err != nil {
		t.Fatalf("parse rotation start JSON returned error: %v", err)
	}
	if strings.TrimSpace(started.OperationID) == "" {
		t.Fatal("rotation start did not return an operation ID")
	}
	activateJSON := run(t, false, hostCtl,
		"rotate", "activate",
		"-state", brokerPath,
		"-operation-id", started.OperationID,
		"-format", "json",
	)
	var activated ctlRotateOutput
	if err := json.Unmarshal([]byte(activateJSON), &activated); err != nil {
		t.Fatalf("parse rotation activate JSON returned error: %v", err)
	}
	if activated.OperationID != started.OperationID {
		t.Fatalf("activated operation = %q, want %q", activated.OperationID, started.OperationID)
	}
	return activated
}

func assertOpenBAORootRotation(t *testing.T, rotationJSON string) {
	t.Helper()
	var output ctlRotateOutput
	if err := json.Unmarshal([]byte(rotationJSON), &output); err != nil {
		t.Fatalf("parse openbao-root JSON returned error: %v", err)
	}
	if output.HTTPStatus < 200 || output.HTTPStatus >= 300 {
		t.Fatalf("openbao-root HTTP status = %d, want 2xx", output.HTTPStatus)
	}
}

func writeOpenBaoConfig(t *testing.T, path string, pluginSHA string) {
	t.Helper()
	config := fmt.Sprintf(`plugin_directory = "/plugins"

plugin "kms" "attested-unseal" {
  command   = "bao-kms-unseal"
  sha256sum = %q
}

seal "attested-unseal" {
  mode        = "local-tpm"
  cluster_id  = "prod-eu1"
  key_id      = "root"
  key_version = "1"
  state_path  = "/state"
  tpm_device  = "/tpm/swtpm.sock"
}

storage "file" {
  path = "/bao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = %q
ui = false
`, pluginSHA, baoAddr)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile OpenBao config returned error: %v", err)
	}
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s returned error: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func startOpenBao(
	t *testing.T,
	image string,
	name string,
	tpmVolume string,
	stateVolume string,
	baoVolume string,
	traceVolume string,
	pluginDir string,
	configDir string,
) {
	t.Helper()
	docker(t, false,
		"run", "-d",
		"--name", name,
		"--cap-add", "IPC_LOCK",
		"-e", "BAO_ADDR="+baoAddr,
		"-e", "OPENBAO_ATTESTED_UNSEAL_TRACE_FILE=/trace/kms.jsonl",
		"-v", tpmVolume+":/tpm",
		"-v", stateVolume+":/state",
		"-v", baoVolume+":/bao",
		"-v", traceVolume+":/trace",
		"-v", pluginDir+":/plugins:ro",
		"-v", configDir+":/config:ro",
		image,
		"server",
		"-config=/config/openbao.hcl",
	)
	waitForAnyStatus(t, name, 30*time.Second)
}

func waitForAnyStatus(t *testing.T, container string, timeout time.Duration) baoStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastOutput string
	for time.Now().Before(deadline) {
		status, output, ok := statusJSON(container)
		if ok {
			return status
		}
		lastOutput = output
		failIfContainerStopped(t, container)
		time.Sleep(500 * time.Millisecond)
	}
	dumpOpenBaoLogs(t, container)
	t.Fatalf("OpenBao status did not become readable: %s", lastOutput)
	return baoStatus{}
}

func waitForStatus(t *testing.T, container string, initialized bool, sealed bool, timeout time.Duration) baoStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastStatus baoStatus
	var lastOutput string
	for time.Now().Before(deadline) {
		status, output, ok := statusJSON(container)
		if ok {
			lastStatus = status
			if status.Initialized == initialized && status.Sealed == sealed {
				return status
			}
		}
		lastOutput = output
		failIfContainerStopped(t, container)
		time.Sleep(time.Second)
	}
	dumpOpenBaoLogs(t, container)
	t.Fatalf(
		"OpenBao status mismatch: got initialized=%t sealed=%t type=%q output=%s",
		lastStatus.Initialized,
		lastStatus.Sealed,
		lastStatus.Type,
		lastOutput,
	)
	return baoStatus{}
}

func statusJSON(container string) (baoStatus, string, bool) {
	output, _ := dockerOutput(
		"exec",
		"-e", "BAO_ADDR="+baoAddr,
		container,
		"bao", "status", "-format=json",
	)
	var status baoStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		return baoStatus{}, output, false
	}
	return status, output, true
}

func assertStatus(t *testing.T, status baoStatus, initialized bool, sealed bool) {
	t.Helper()
	if status.Type != "attested" {
		t.Fatalf("OpenBao seal type = %q, want attested", status.Type)
	}
	if status.Initialized != initialized || status.Sealed != sealed {
		t.Fatalf(
			"OpenBao status initialized=%t sealed=%t, want initialized=%t sealed=%t",
			status.Initialized,
			status.Sealed,
			initialized,
			sealed,
		)
	}
}

func waitForTraceOperationCount(
	t *testing.T,
	alpineImage string,
	traceVolume string,
	operation string,
	want int,
	timeout time.Duration,
) []kmsTraceEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var events []kmsTraceEvent
	for time.Now().Before(deadline) {
		events = readTraceEvents(t, alpineImage, traceVolume)
		if countTraceOperation(events, operation) >= want {
			return events
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf(
		"KMS trace operation %q count = %d, want at least %d; events=%+v",
		operation,
		countTraceOperation(events, operation),
		want,
		events,
	)
	return nil
}

func readTraceEvents(t *testing.T, alpineImage string, traceVolume string) []kmsTraceEvent {
	t.Helper()
	output := docker(t, false,
		"run", "--rm",
		"-v", traceVolume+":/trace:ro",
		alpineImage,
		"sh", "-lc", "test ! -f /trace/kms.jsonl || cat /trace/kms.jsonl",
	)
	scanner := bufio.NewScanner(strings.NewReader(output))
	events := make([]kmsTraceEvent, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event kmsTraceEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("parse KMS trace event returned error: %v\n%s", err, line)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan KMS trace returned error: %v", err)
	}
	return events
}

func countTraceOperation(events []kmsTraceEvent, operation string) int {
	count := 0
	for _, event := range events {
		if event.Operation == operation {
			count++
		}
	}
	return count
}

func assertLastTraceKeyID(t *testing.T, events []kmsTraceEvent, operation string, keyID string) {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Operation != operation {
			continue
		}
		if events[i].KeyID != keyID {
			t.Fatalf("last %s trace key ID = %q, want %q", operation, events[i].KeyID, keyID)
		}
		return
	}
	t.Fatalf("KMS trace did not contain operation %q", operation)
}

func failIfContainerStopped(t *testing.T, container string) {
	t.Helper()
	output := docker(t, false, "ps", "--filter", "name="+container, "--format", "{{.Names}}")
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == container {
			return
		}
	}
	dumpOpenBaoLogs(t, container)
	t.Fatalf("container %s stopped", container)
}

func dumpOpenBaoLogs(t *testing.T, container string) {
	t.Helper()
	output, err := dockerOutput("logs", container)
	if err != nil && strings.TrimSpace(output) == "" {
		t.Logf("docker logs %s failed: %v", container, err)
		return
	}
	t.Logf("OpenBao logs for %s:\n%s", container, output)
}

func docker(t *testing.T, sensitive bool, args ...string) string {
	t.Helper()
	return run(t, sensitive, "docker", args...)
}

func dockerIgnore(t *testing.T, args ...string) {
	t.Helper()
	_, _ = dockerOutput(args...)
}

func dockerOutput(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	//nolint:gosec // E2E harness intentionally invokes the local Docker CLI.
	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return string(output), ctx.Err()
	}
	return string(output), err
}

func run(t *testing.T, sensitive bool, name string, args ...string) string {
	t.Helper()
	return runWithEnv(t, sensitive, "", os.Environ(), name, args...)
}

func runWithEnv(t *testing.T, sensitive bool, dir string, env []string, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	//nolint:gosec // E2E harness intentionally invokes local build and container commands.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output)
	}
	if sensitive {
		t.Fatalf("%s failed: %v; output suppressed because it may contain recovery material", name, err)
	}
	t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, string(output))
	return ""
}
