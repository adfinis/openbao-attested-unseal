//go:build e2e

package openbao

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

type tcHarness struct {
	t       *testing.T
	ctx     context.Context
	network *testcontainers.DockerNetwork
}

type tcBinaries struct {
	Plugin string
	Ctl    string
	Broker string
}

type tcOpenBaoNode struct {
	Name      string
	Alias     string
	Container *testcontainers.DockerContainer
}

func newTCHarness(t *testing.T) *tcHarness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	nw, err := tcnetwork.New(ctx)
	if err != nil {
		t.Fatalf("create testcontainers network returned error: %v", err)
	}
	t.Cleanup(func() {
		if os.Getenv("OPENBAO_E2E_KEEP") == "1" {
			t.Logf("OPENBAO_E2E_KEEP=1; keeping testcontainers network %s id=%s", nw.Name, nw.ID)
			return
		}
		if err := nw.Remove(context.Background()); err != nil {
			t.Logf("remove testcontainers network returned error: %v", err)
		}
	})
	return &tcHarness{t: t, ctx: ctx, network: nw}
}

func buildTCBinaries(t *testing.T, workDir string) tcBinaries {
	t.Helper()
	repoRoot := findRepoRoot(t)
	dockerArch := dockerServerArch(t)
	goarch := dockerGOARCH(t, dockerArch)
	binDir := filepath.Join(workDir, "bin")
	pluginDir := filepath.Join(workDir, "plugins")
	mkdirAll(t, binDir, 0o700)
	mkdirAll(t, pluginDir, 0o700)

	binaries := tcBinaries{
		Plugin: filepath.Join(pluginDir, "bao-kms-unseal"),
		Ctl:    filepath.Join(binDir, "bao-unsealctl-linux"),
		Broker: filepath.Join(binDir, "bao-unseald-linux"),
	}
	buildBinary(t, repoRoot, binaries.Plugin, "linux", goarch, "./cmd/bao-kms-unseal")
	buildBinary(t, repoRoot, binaries.Ctl, "linux", goarch, "./cmd/bao-unsealctl")
	buildBinary(t, repoRoot, binaries.Broker, "linux", goarch, "./cmd/bao-unseald")
	chmod(t, binaries.Plugin, 0o755)
	chmod(t, binaries.Ctl, 0o755)
	chmod(t, binaries.Broker, 0o755)
	return binaries
}

func (h *tcHarness) startBroker(
	image string,
	alias string,
	binaries tcBinaries,
	configPath string,
) *testcontainers.DockerContainer {
	h.t.Helper()
	ctr, err := testcontainers.Run(
		h.ctx,
		image,
		tcnetwork.WithNetwork([]string{alias}, h.network),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath:      binaries.Broker,
				ContainerFilePath: "/usr/local/bin/bao-unseald",
				FileMode:          0o755,
			},
			testcontainers.ContainerFile{
				HostFilePath:      binaries.Ctl,
				ContainerFilePath: "/usr/local/bin/bao-unsealctl",
				FileMode:          0o755,
			},
			testcontainers.ContainerFile{
				HostFilePath:      configPath,
				ContainerFilePath: "/broker/broker.json",
				FileMode:          0o600,
			},
		),
		testcontainers.WithEntrypoint("/usr/local/bin/bao-unseald"),
		testcontainers.WithCmd("serve", "-config", "/broker/broker.json"),
		testcontainers.WithExposedPorts("8201/tcp"),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("8201/tcp").WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		h.t.Fatalf("start broker container returned error: %v", err)
	}
	h.cleanupContainer(ctr, "broker")
	return ctr
}

func (h *tcHarness) startOpenBaoNode(
	image string,
	alias string,
	binaries tcBinaries,
	configPath string,
) tcOpenBaoNode {
	h.t.Helper()
	ctr, err := testcontainers.Run(
		h.ctx,
		image,
		tcnetwork.WithNetwork([]string{alias}, h.network),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath:      binaries.Plugin,
				ContainerFilePath: "/plugins/bao-kms-unseal",
				FileMode:          0o755,
			},
			testcontainers.ContainerFile{
				HostFilePath:      configPath,
				ContainerFilePath: "/config/openbao.hcl",
				FileMode:          0o644,
			},
		),
		testcontainers.WithEnv(map[string]string{
			"BAO_ADDR": "http://127.0.0.1:8200",
		}),
		testcontainers.WithEntrypoint("sh", "-lc"),
		testcontainers.WithCmd("mkdir -p /tmp/openbao/raft && exec bao server -config=/config/openbao.hcl"),
		testcontainers.WithExposedPorts("8200/tcp", "8201/tcp"),
		testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
			hostConfig.CapAdd = append(hostConfig.CapAdd, "IPC_LOCK")
		}),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("8200/tcp").WithStartupTimeout(45*time.Second)),
	)
	if err != nil {
		h.t.Fatalf("start OpenBao container %s returned error: %v", alias, err)
	}
	h.cleanupContainer(ctr, alias)
	return tcOpenBaoNode{Name: alias, Alias: alias, Container: ctr}
}

func (h *tcHarness) cleanupContainer(ctr *testcontainers.DockerContainer, label string) {
	h.t.Helper()
	h.t.Cleanup(func() {
		if os.Getenv("OPENBAO_E2E_KEEP") == "1" {
			h.t.Logf(
				"OPENBAO_E2E_KEEP=1; keeping testcontainers container %s id=%s; set TESTCONTAINERS_RYUK_DISABLED=true if the reaper removes it",
				label,
				ctr.GetContainerID(),
			)
			return
		}
		if err := ctr.Terminate(context.Background()); err != nil {
			h.t.Logf("terminate %s returned error: %v", label, err)
		}
	})
}

func tcExec(t *testing.T, ctr *testcontainers.DockerContainer, cmd []string, opts ...tcexec.ProcessOption) string {
	t.Helper()
	output, code := tcExecAllowExit(t, ctr, cmd, opts...)
	if code != 0 {
		t.Fatalf("container exec %q exit code = %d output=%s", strings.Join(cmd, " "), code, output)
	}
	return output
}

func tcExecAllowExit(
	t *testing.T,
	ctr *testcontainers.DockerContainer,
	cmd []string,
	opts ...tcexec.ProcessOption,
) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	opts = append(opts, tcexec.Multiplexed())
	code, reader, err := ctr.Exec(ctx, cmd, opts...)
	if err != nil {
		t.Fatalf("container exec %q returned error: %v", strings.Join(cmd, " "), err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read exec output returned error: %v", err)
	}
	return string(body), code
}

func waitForTCStatus(
	t *testing.T,
	node tcOpenBaoNode,
	initialized bool,
	sealed bool,
	timeout time.Duration,
) baoStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastStatus baoStatus
	var lastOutput string
	for time.Now().Before(deadline) {
		output, _ := tcExecAllowExit(t, node.Container, []string{"bao", "status", "-format=json"})
		var status baoStatus
		if err := json.Unmarshal([]byte(output), &status); err == nil {
			lastStatus = status
			if status.Initialized == initialized && status.Sealed == sealed {
				return status
			}
		}
		lastOutput = output
		failIfTCContainerStopped(t, node)
		time.Sleep(time.Second)
	}
	dumpTCLogs(t, node.Container, node.Name)
	t.Fatalf(
		"OpenBao %s status mismatch: got initialized=%t sealed=%t output=%s",
		node.Name,
		lastStatus.Initialized,
		lastStatus.Sealed,
		lastOutput,
	)
	return baoStatus{}
}

func failIfTCContainerStopped(t *testing.T, node tcOpenBaoNode) {
	t.Helper()
	state, err := node.Container.State(context.Background())
	if err != nil {
		t.Fatalf("inspect OpenBao %s returned error: %v", node.Name, err)
	}
	if !state.Running {
		dumpTCLogs(t, node.Container, node.Name)
		t.Fatalf("OpenBao %s container stopped", node.Name)
	}
}

func dumpTCLogs(t *testing.T, ctr *testcontainers.DockerContainer, label string) {
	t.Helper()
	logs, err := ctr.Logs(context.Background())
	if err != nil {
		t.Logf("read %s logs returned error: %v", label, err)
		return
	}
	defer func() { _ = logs.Close() }()
	body, err := io.ReadAll(logs)
	if err != nil {
		t.Logf("read %s logs body returned error: %v", label, err)
		return
	}
	t.Logf("%s logs:\n%s", label, body)
}

func writeTCBrokerConfig(t *testing.T, path string) {
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

func brokerDevelopmentWrappingKeyB64() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
}
