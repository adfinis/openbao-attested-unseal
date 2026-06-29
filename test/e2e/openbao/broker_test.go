//go:build e2e

package openbao

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBrokerAutoUnsealWithOpenBaoBeta(t *testing.T) {
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
	brokerDir := filepath.Join(workDir, "broker")
	mkdirAll(t, binDir, 0o700)
	mkdirAll(t, pluginDir, 0o700)
	mkdirAll(t, configDir, 0o700)
	mkdirAll(t, brokerDir, 0o700)

	hostCtl := filepath.Join(binDir, "bao-unsealctl-host")
	linuxCtl := filepath.Join(binDir, "bao-unsealctl-linux")
	linuxBroker := filepath.Join(binDir, "bao-unseald-linux")
	pluginPath := filepath.Join(pluginDir, "bao-kms-unseal")
	buildBinary(t, repoRoot, hostCtl, "", "", "./cmd/bao-unsealctl")
	buildBinary(t, repoRoot, linuxCtl, "linux", goarch, "./cmd/bao-unsealctl")
	buildBinary(t, repoRoot, linuxBroker, "linux", goarch, "./cmd/bao-unseald")
	buildBinary(t, repoRoot, pluginPath, "linux", goarch, "./cmd/bao-kms-unseal")
	chmod(t, linuxCtl, 0o755)
	chmod(t, linuxBroker, 0o755)
	chmod(t, pluginPath, 0o755)

	runID := fmt.Sprintf("openbao-au-broker-e2e-%d-%d", time.Now().UnixNano(), os.Getpid())
	networkName := runID + "-net"
	baoVolume := runID + "-bao"
	traceVolume := runID + "-trace"
	brokerName := runID + "-broker"
	baoName := runID + "-bao"
	keep := os.Getenv("OPENBAO_E2E_KEEP") == "1"
	if !keep {
		t.Cleanup(func() {
			dockerIgnore(t, "rm", "-f", baoName, brokerName)
			dockerIgnore(t, "volume", "rm", baoVolume, traceVolume)
			dockerIgnore(t, "network", "rm", networkName)
		})
		t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	} else {
		t.Logf("OPENBAO_E2E_KEEP=1; keeping work dir %s and Docker resources with prefix %s", workDir, runID)
	}

	docker(t, false, "network", "create", networkName)
	docker(t, false, "volume", "create", baoVolume)
	docker(t, false, "volume", "create", traceVolume)
	docker(t, false,
		"run", "--rm",
		"-v", baoVolume+":/bao",
		"-v", traceVolume+":/trace",
		alpineImage,
		"sh", "-lc", "chown -R 100:1000 /bao /trace && chmod -R go-rwx /trace || true",
	)
	brokerConfigPath := filepath.Join(brokerDir, "broker.json")
	brokerDBPath := filepath.Join(brokerDir, "broker.db")
	writeBrokerConfig(t, brokerConfigPath)
	startBroker(t, alpineImage, brokerName, networkName, linuxBroker, brokerDir)
	waitForBrokerPort(t, alpineImage, networkName, brokerName)

	writeOpenBaoBrokerConfig(
		t,
		filepath.Join(configDir, "openbao.hcl"),
		sha256Hex(t, pluginPath),
		brokerName+":8201",
	)
	startOpenBaoBroker(t, openbaoImage, baoName, networkName, baoVolume, traceVolume, pluginDir, configDir)
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
	assertLastTraceKeyID(t, beforeRotateEvents, "encrypt", "prod-eu1/root/v1")
	beforeRotateEncryptCount := countTraceOperation(beforeRotateEvents, "encrypt")
	operation := startActivatedRotation(t, hostCtl, brokerDBPath)
	openBAORootJSON := docker(t, true,
		"run", "--rm",
		"--network", networkName,
		"-e", "BAO_ADDR=http://"+baoName+":8200",
		"-e", "BAO_TOKEN="+openBaoInit.RootToken,
		"-v", linuxCtl+":/usr/local/bin/bao-unsealctl:ro",
		"-v", brokerDBPath+":/broker.db",
		alpineImage,
		"/usr/local/bin/bao-unsealctl",
		"rotate", "openbao-root",
		"-state", "/broker.db",
		"-operation-id", operation.OperationID,
		"-addr", "http://"+baoName+":8200",
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
	assertLastTraceKeyID(t, afterRotateEvents, "encrypt", "prod-eu1/root/v2")
	decryptCountBeforeRestart := countTraceOperation(afterRotateEvents, "decrypt")

	docker(t, false, "rm", "-f", baoName)
	startOpenBaoBroker(t, openbaoImage, baoName, networkName, baoVolume, traceVolume, pluginDir, configDir)
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
	assertTraceKeyIDAfterCount(t, afterRestartEvents, "decrypt", "prod-eu1/root/v2", decryptCountBeforeRestart)

	restartJSON := docker(t, true,
		"run", "--rm",
		"--network", networkName,
		"-e", "BAO_ADDR=http://"+baoName+":8200",
		"-v", linuxCtl+":/usr/local/bin/bao-unsealctl:ro",
		"-v", brokerDBPath+":/broker.db",
		alpineImage,
		"/usr/local/bin/bao-unsealctl",
		"rotate", "verify-restart",
		"-state", "/broker.db",
		"-operation-id", operation.OperationID,
		"-addr", "http://"+baoName+":8200",
		"-format", "json",
	)
	assertRestartVerification(t, restartJSON)
}

func writeBrokerConfig(t *testing.T, path string) {
	t.Helper()
	config := fmt.Sprintf(`{
  "listen_address": "0.0.0.0:8201",
  "allow_plaintext_for_tests": true,
  "sqlite_path": "/broker/broker.db",
  "audit_file_path": "/broker/audit.jsonl",
  "otel_exporter": "none",
  "keyring_protection_profile": "development",
  "cluster_id": "prod-eu1",
  "key_id": "root",
  "policy_id": "development",
  "development_subject": "node-a",
  "development_wrapping_key_b64": %q,
  "challenge_ttl_seconds": 60
}
`, brokerDevelopmentWrappingKeyB64())
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile broker config returned error: %v", err)
	}
}

func startBroker(
	t *testing.T,
	alpineImage string,
	name string,
	networkName string,
	linuxBroker string,
	brokerDir string,
) {
	t.Helper()
	docker(t, false,
		"run", "-d",
		"--name", name,
		"--network", networkName,
		"-v", linuxBroker+":/usr/local/bin/bao-unseald:ro",
		"-v", brokerDir+":/broker",
		alpineImage,
		"/usr/local/bin/bao-unseald",
		"serve",
		"-config", "/broker/broker.json",
	)
}

func waitForBrokerPort(t *testing.T, alpineImage string, networkName string, brokerName string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var lastOutput string
	for time.Now().Before(deadline) {
		output, err := dockerOutput(
			"run", "--rm",
			"--network", networkName,
			alpineImage,
			"sh", "-lc", "nc -z "+brokerName+" 8201",
		)
		if err == nil {
			return
		}
		lastOutput = strings.TrimSpace(output)
		if containerStopped(brokerName) {
			dumpContainerLogs(t, brokerName, "broker")
			t.Fatalf("broker container %s stopped", brokerName)
		}
		time.Sleep(250 * time.Millisecond)
	}
	dumpContainerLogs(t, brokerName, "broker")
	t.Fatalf("broker port did not become ready: %s", lastOutput)
}

func writeOpenBaoBrokerConfig(t *testing.T, path string, pluginSHA string, brokerAddress string) {
	t.Helper()
	config := fmt.Sprintf(`plugin_directory = "/plugins"

plugin "kms" "attested-unseal" {
  command   = "bao-kms-unseal"
  sha256sum = %q
}

seal "attested-unseal" {
  mode             = "broker"
  broker_addr      = %q
  broker_plaintext = "true"
  cluster_id       = "prod-eu1"
  node_id          = "node-a"
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
`, pluginSHA, brokerAddress, baoAddr)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile OpenBao broker config returned error: %v", err)
	}
}

func startOpenBaoBroker(
	t *testing.T,
	image string,
	name string,
	networkName string,
	baoVolume string,
	traceVolume string,
	pluginDir string,
	configDir string,
) {
	t.Helper()
	docker(t, false,
		"run", "-d",
		"--name", name,
		"--network", networkName,
		"--cap-add", "IPC_LOCK",
		"-e", "BAO_ADDR="+baoAddr,
		"-e", "OPENBAO_ATTESTED_UNSEAL_TRACE_FILE=/trace/kms.jsonl",
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

func containerStopped(container string) bool {
	output, _ := dockerOutput("ps", "--filter", "name="+container, "--format", "{{.Names}}")
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == container {
			return false
		}
	}
	return true
}

func dumpContainerLogs(t *testing.T, container string, label string) {
	t.Helper()
	output, err := dockerOutput("logs", container)
	if err != nil && strings.TrimSpace(output) == "" {
		t.Logf("docker logs %s failed: %v", container, err)
		return
	}
	t.Logf("%s logs for %s:\n%s", label, container, output)
}

func assertTraceKeyIDAfterCount(
	t *testing.T,
	events []kmsTraceEvent,
	operation string,
	keyID string,
	seenBefore int,
) {
	t.Helper()
	seen := 0
	for _, event := range events {
		if event.Operation != operation {
			continue
		}
		seen++
		if seen <= seenBefore {
			continue
		}
		if event.KeyID == keyID {
			return
		}
	}
	t.Fatalf("KMS trace did not contain %s with key ID %q after %d previous events: %+v", operation, keyID, seenBefore, events)
}
