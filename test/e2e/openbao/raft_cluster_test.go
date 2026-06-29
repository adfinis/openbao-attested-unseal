//go:build e2e

package openbao

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
)

func TestBrokerRaft3NodeAutoUnsealWithOpenBaoBeta(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Docker-backed E2E is not supported on Windows")
	}
	requireDocker(t)

	openbaoImage := envDefault("OPENBAO_E2E_IMAGE", defaultOpenBaoImage)
	alpineImage := envDefault("OPENBAO_E2E_ALPINE_IMAGE", defaultAlpineImage)
	pullImageIfMissing(t, openbaoImage)
	pullImageIfMissing(t, alpineImage)

	workDir := newE2EWorkDir(t)
	if os.Getenv("OPENBAO_E2E_KEEP") != "1" {
		t.Cleanup(func() { _ = os.RemoveAll(workDir) })
	} else {
		t.Logf("OPENBAO_E2E_KEEP=1; keeping work dir %s", workDir)
	}
	binaries := buildTCBinaries(t, workDir)
	configDir := filepath.Join(workDir, "config")
	mkdirAll(t, configDir, 0o700)

	harness := newTCHarness(t)
	brokerConfig := filepath.Join(configDir, "broker.json")
	writeTCBrokerConfig(t, brokerConfig)
	broker := harness.startBroker(alpineImage, "broker", binaries, brokerConfig)

	leaderConfigPath := filepath.Join(configDir, "bao-0.hcl")
	writeOpenBaoRaftBrokerConfig(t, leaderConfigPath, "bao-0", "broker:8201", sha256Hex(t, binaries.Plugin))
	leader := harness.startOpenBaoNode(openbaoImage, "bao-0", binaries, leaderConfigPath)
	nodes := []tcOpenBaoNode{leader}
	before := waitForTCStatus(t, leader, false, true, 30*time.Second)
	assertStatus(t, before, false, true)

	initJSON := tcExec(
		t,
		leader.Container,
		[]string{"bao", "operator", "init", "-recovery-shares=1", "-recovery-threshold=1", "-format=json"},
		tcexec.WithEnv([]string{"BAO_ADDR=http://127.0.0.1:8200"}),
	)
	init := parseOpenBaoInit(t, initJSON)
	leaderStatus := waitForTCStatus(t, leader, true, false, 90*time.Second)
	assertStatus(t, leaderStatus, true, false)

	for i := 1; i < 3; i++ {
		alias := fmt.Sprintf("bao-%d", i)
		configPath := filepath.Join(configDir, alias+".hcl")
		writeOpenBaoRaftBrokerConfig(t, configPath, alias, "broker:8201", sha256Hex(t, binaries.Plugin))
		node := harness.startOpenBaoNode(openbaoImage, alias, binaries, configPath)
		joinOpenBaoRaftNode(t, node, "bao-0")
		status := waitForTCStatus(t, node, true, false, 90*time.Second)
		assertStatus(t, status, true, false)
		nodes = append(nodes, node)
	}
	assertRaftPeersFromEveryNode(t, nodes, init.RootToken, []string{"bao-0", "bao-1", "bao-2"})
	enableE2EKVMount(t, nodes[0], init.RootToken)
	beforeRestartMarker := assertKVWriteRead(
		t,
		nodes[1],
		nodes[2],
		init.RootToken,
		"before-restart",
	)

	operation := startActivatedRotationInBroker(t, broker)
	openBAORootJSON := tcExec(
		t,
		broker,
		[]string{
			"/usr/local/bin/bao-unsealctl",
			"rotate", "openbao-root",
			"-state", "/broker/broker.db",
			"-operation-id", operation.OperationID,
			"-addr", "http://bao-0:8200",
			"-format", "json",
		},
		tcexec.WithEnv([]string{"BAO_TOKEN=" + init.RootToken}),
	)
	assertOpenBAORootRotation(t, openBAORootJSON)

	restartTCOpenBaoNodes(t, nodes)
	for _, node := range nodes {
		status := waitForTCStatus(t, node, true, false, 90*time.Second)
		assertStatus(t, status, true, false)
	}
	assertRaftPeersFromEveryNode(t, nodes, init.RootToken, []string{"bao-0", "bao-1", "bao-2"})
	assertKVRead(t, nodes[1], init.RootToken, "before-restart", beforeRestartMarker)
	assertKVWriteRead(t, nodes[2], nodes[1], init.RootToken, "after-restart")
	restartJSON := tcExec(
		t,
		broker,
		[]string{
			"/usr/local/bin/bao-unsealctl",
			"rotate", "verify-restart",
			"-state", "/broker/broker.db",
			"-operation-id", operation.OperationID,
			"-addr", "http://bao-0:8200",
			"-format", "json",
		},
	)
	assertRestartVerification(t, restartJSON)
}

func writeOpenBaoRaftBrokerConfig(
	t *testing.T,
	path string,
	nodeID string,
	brokerAddress string,
	pluginSHA string,
) {
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

storage "raft" {
  path    = "/tmp/openbao/raft"
  node_id = %q
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = true
}

api_addr     = "http://%s:8200"
cluster_addr = "http://%s:8201"
ui = false
`, pluginSHA, brokerAddress, nodeID, nodeID, nodeID)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("WriteFile OpenBao raft config returned error: %v", err)
	}
}

func joinOpenBaoRaftNode(t *testing.T, node tcOpenBaoNode, leaderAlias string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var lastOutput string
	for time.Now().Before(deadline) {
		output, code := tcExecAllowExit(
			t,
			node.Container,
			[]string{"bao", "operator", "raft", "join", "http://" + leaderAlias + ":8200"},
			tcexec.WithEnv([]string{"BAO_ADDR=http://127.0.0.1:8200"}),
		)
		if code == 0 {
			return
		}
		lastOutput = output
		failIfTCContainerStopped(t, node)
		time.Sleep(time.Second)
	}
	dumpTCLogs(t, node.Container, node.Name)
	t.Fatalf("raft join for %s did not complete: %s", node.Name, lastOutput)
}

func startActivatedRotationInBroker(t *testing.T, broker *testcontainers.DockerContainer) ctlRotateOutput {
	t.Helper()
	startJSON := tcExec(t, broker, []string{
		"/usr/local/bin/bao-unsealctl",
		"rotate", "start",
		"-state", "/broker/broker.db",
		"-cluster-id", "prod-eu1",
		"-key-id", "root",
		"-policy-id", "rotation",
		"-format", "json",
	})
	var started ctlRotateOutput
	if err := json.Unmarshal([]byte(startJSON), &started); err != nil {
		t.Fatalf("parse rotation start JSON returned error: %v", err)
	}
	if strings.TrimSpace(started.OperationID) == "" {
		t.Fatal("rotation start did not return an operation ID")
	}
	activateJSON := tcExec(t, broker, []string{
		"/usr/local/bin/bao-unsealctl",
		"rotate", "activate",
		"-state", "/broker/broker.db",
		"-operation-id", started.OperationID,
		"-format", "json",
	})
	var activated ctlRotateOutput
	if err := json.Unmarshal([]byte(activateJSON), &activated); err != nil {
		t.Fatalf("parse rotation activate JSON returned error: %v", err)
	}
	if activated.OperationID != started.OperationID {
		t.Fatalf("activated operation = %q, want %q", activated.OperationID, started.OperationID)
	}
	return activated
}

func assertRaftPeers(t *testing.T, leader tcOpenBaoNode, rootToken string, want []string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var output string
	for time.Now().Before(deadline) {
		output = tcExec(
			t,
			leader.Container,
			[]string{"bao", "operator", "raft", "list-peers", "-format=json"},
			tcexec.WithEnv([]string{"BAO_ADDR=http://127.0.0.1:8200", "BAO_TOKEN=" + rootToken}),
		)
		var peers raftPeersOutput
		if err := json.Unmarshal([]byte(output), &peers); err != nil {
			t.Fatalf("parse raft peers returned error: %v\n%s", err, output)
		}
		got := peers.NodeIDs()
		wantSorted := slices.Clone(want)
		slices.Sort(got)
		slices.Sort(wantSorted)
		if slices.Equal(got, wantSorted) {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("raft peers did not converge to %v; raw=%s", want, output)
}

func assertRaftPeersFromEveryNode(t *testing.T, nodes []tcOpenBaoNode, rootToken string, want []string) {
	t.Helper()
	for _, node := range nodes {
		assertRaftPeers(t, node, rootToken, want)
	}
}

type raftPeersOutput struct {
	Data    raftPeersData `json:"data"`
	Config  raftConfig    `json:"config"`
	Servers []raftPeer    `json:"servers"`
}

type raftPeersData struct {
	Config raftConfig `json:"config"`
}

type raftConfig struct {
	Servers []raftPeer `json:"servers"`
}

type raftPeer struct {
	NodeID string `json:"node_id"`
}

func (o raftPeersOutput) NodeIDs() []string {
	servers := o.Data.Config.Servers
	if len(servers) == 0 {
		servers = o.Config.Servers
	}
	if len(servers) == 0 {
		servers = o.Servers
	}
	out := make([]string, 0, len(servers))
	for _, server := range servers {
		out = append(out, server.NodeID)
	}
	return out
}

func enableE2EKVMount(t *testing.T, node tcOpenBaoNode, rootToken string) {
	t.Helper()
	tcExec(
		t,
		node.Container,
		[]string{"bao", "secrets", "enable", "-path=au-e2e", "kv"},
		tcexec.WithEnv(openBaoClientEnv(rootToken)),
	)
}

func assertKVWriteRead(
	t *testing.T,
	writer tcOpenBaoNode,
	reader tcOpenBaoNode,
	rootToken string,
	label string,
) string {
	t.Helper()
	marker := fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
	path := "au-e2e/" + label
	retryTCExec(
		t,
		writer.Container,
		[]string{"bao", "write", path, "marker=" + marker},
		45*time.Second,
		writer,
		tcexec.WithEnv(openBaoClientEnv(rootToken)),
	)
	assertKVRead(t, reader, rootToken, label, marker)
	return marker
}

func assertKVRead(t *testing.T, node tcOpenBaoNode, rootToken string, label string, wantMarker string) {
	t.Helper()
	output := retryTCExec(
		t,
		node.Container,
		[]string{"bao", "read", "-format=json", "au-e2e/" + label},
		45*time.Second,
		node,
		tcexec.WithEnv(openBaoClientEnv(rootToken)),
	)
	var read kvReadOutput
	if err := json.Unmarshal([]byte(output), &read); err != nil {
		t.Fatalf("parse KV read returned error: %v\n%s", err, output)
	}
	if read.Data.Marker != wantMarker {
		t.Fatalf("KV marker read through %s = %q, want %q; raw=%s", node.Name, read.Data.Marker, wantMarker, output)
	}
}

type kvReadOutput struct {
	Data struct {
		Marker string `json:"marker"`
	} `json:"data"`
}

func retryTCExec(
	t *testing.T,
	ctr *testcontainers.DockerContainer,
	cmd []string,
	timeout time.Duration,
	node tcOpenBaoNode,
	opts ...tcexec.ProcessOption,
) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastOutput string
	for time.Now().Before(deadline) {
		output, code := tcExecAllowExit(t, ctr, cmd, opts...)
		if code == 0 {
			return output
		}
		lastOutput = output
		failIfTCContainerStopped(t, node)
		time.Sleep(time.Second)
	}
	dumpTCLogs(t, node.Container, node.Name)
	t.Fatalf("container exec %q did not complete: %s", strings.Join(cmd, " "), lastOutput)
	return ""
}

func openBaoClientEnv(rootToken string) []string {
	return []string{"BAO_ADDR=http://127.0.0.1:8200", "BAO_TOKEN=" + rootToken}
}

func restartTCOpenBaoNodes(t *testing.T, nodes []tcOpenBaoNode) {
	t.Helper()
	timeout := 10 * time.Second
	for _, node := range nodes {
		if err := node.Container.Stop(context.Background(), &timeout); err != nil {
			t.Fatalf("stop %s returned error: %v", node.Name, err)
		}
	}
	for _, node := range nodes {
		if err := node.Container.Start(context.Background()); err != nil {
			t.Fatalf("start %s returned error: %v", node.Name, err)
		}
	}
}
