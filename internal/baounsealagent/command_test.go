package baounsealagent

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeagent"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

const (
	testClusterID  = "prod-eu1"
	testNodeName   = "kind-worker"
	testNodeUID    = "node-uid-1"
	testDecision   = "allow"
	testStatus     = "fresh"
	testFormatJSON = "json"
)

func TestPublishOnceJSON(t *testing.T) {
	address, cache := startAdminBrokerTestServer(t)

	var out publishOnceOutput
	runJSON(t, &out,
		"publish-once",
		"-addr", address,
		"-plaintext",
		"-cluster-id", testClusterID,
		"-node-name", testNodeName,
		"-node-uid", testNodeUID,
		"-ttl", "1m",
		"-format", testFormatJSON,
	)

	expected, err := (nodeagent.FakeLocalProvider{}).CollectNodeEvidence(context.Background(), nodeagent.PublishRequest{
		ClusterID: testClusterID,
		NodeName:  testNodeName,
		NodeUID:   testNodeUID,
		TTL:       time.Minute,
	})
	if err != nil {
		t.Fatalf("CollectNodeEvidence returned error: %v", err)
	}
	if out.Decision != testDecision ||
		out.Status != testStatus ||
		out.ProviderID != broker.NodeEvidenceProviderFakeLocal ||
		out.EvidenceHash != expected.EvidenceHash {
		t.Fatalf("publish output = %#v, want fake-local allow", out)
	}

	evidence, err := cache.NodeEvidence(context.Background(), testClusterID, testNodeName)
	if err != nil {
		t.Fatalf("NodeEvidence returned error: %v", err)
	}
	if evidence.EvidenceHash != out.EvidenceHash || evidence.NodeUID != testNodeUID {
		t.Fatalf("stored evidence = %#v, want command output hash and node UID", evidence)
	}
}

func TestPublishOnceUsesNodeEnvironment(t *testing.T) {
	address, _ := startAdminBrokerTestServer(t)
	t.Setenv("BAO_UNSEAL_CLUSTER_ID", testClusterID)
	t.Setenv("NODE_NAME", testNodeName)
	t.Setenv("NODE_UID", testNodeUID)

	var out publishOnceOutput
	runJSON(t, &out,
		"publish-once",
		"-addr", address,
		"-plaintext",
		"-ttl", "1m",
		"-format", testFormatJSON,
	)
	if out.ClusterID != testClusterID || out.NodeName != testNodeName || out.NodeUID != testNodeUID {
		t.Fatalf("publish output = %#v, want environment-derived node identity", out)
	}
}

func TestPublishOnceRejectsMissingNodeName(t *testing.T) {
	t.Setenv("NODE_NAME", "")

	err := runCommand(
		"publish-once",
		"-addr", "127.0.0.1:1",
		"-plaintext",
		"-cluster-id", testClusterID,
		"-format", testFormatJSON,
	)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitUsage)
	}
}

func TestUsageListsPublishOnce(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(version.Info{Version: "test"}, []string{"help"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "bao-unseal-agent publish-once") {
		t.Fatalf("usage output = %q, want publish-once command", stdout.String())
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
