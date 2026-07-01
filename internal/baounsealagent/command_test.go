package baounsealagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

var errPublishFailed = errors.New("publish failed")

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

	err := runExecuteCommand(
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

func TestRunLoopPublishesUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Unix(1_800_000_000, 0).UTC()
	var events []runEvent
	publishCount := 0
	waitCount := 0
	loop := agentRunLoop{
		interval: time.Second,
		publish: func(context.Context) (publishOnceOutput, error) {
			publishCount++
			return publishOnceOutput{
				ClusterID:    testClusterID,
				NodeName:     testNodeName,
				NodeUID:      testNodeUID,
				ProviderID:   broker.NodeEvidenceProviderFakeLocal,
				EvidenceHash: "hash",
				ExpiresAt:    now.Add(time.Minute).Format(time.RFC3339),
				Status:       testStatus,
				Decision:     testDecision,
			}, nil
		},
		write: func(event runEvent) error {
			events = append(events, event)
			return nil
		},
		wait: func(ctx context.Context, _ time.Duration) error {
			waitCount++
			if waitCount == 2 {
				cancel()
				return context.Canceled
			}
			return ctx.Err()
		},
		now: func() time.Time { return now },
	}

	err := loop.Run(ctx, publishOptionsFixture())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if publishCount != 2 || len(events) != 2 {
		t.Fatalf("published %d times with %d events, want 2 each", publishCount, len(events))
	}
	for _, event := range events {
		if event.Event != runEventPublished ||
			event.ClusterID != testClusterID ||
			event.NodeName != testNodeName ||
			event.Attempt == 0 {
			t.Fatalf("event = %#v, want successful publish event", event)
		}
	}
}

func TestRunLoopStopsAfterMaxFailures(t *testing.T) {
	var events []runEvent
	loop := agentRunLoop{
		interval:    time.Second,
		maxFailures: 2,
		publish: func(context.Context) (publishOnceOutput, error) {
			return publishOnceOutput{}, errPublishFailed
		},
		write: func(event runEvent) error {
			events = append(events, event)
			return nil
		},
		wait: func(context.Context, time.Duration) error { return nil },
	}

	err := loop.Run(context.Background(), publishOptionsFixture())
	if !errors.Is(err, errPublishFailed) {
		t.Fatalf("Run error = %v, want publish failure", err)
	}
	if got := cli.ProcessExitCode(err); got != int(cli.ExitRuntime) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitRuntime)
	}
	if len(events) != 2 ||
		events[0].FailureCount != 1 ||
		events[1].FailureCount != 2 ||
		events[1].Event != runEventFailed {
		t.Fatalf("events = %#v, want two failure events", events)
	}
}

func TestParseRunOptionsRejectsIntervalAtTTL(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseRunOptions([]string{
		"-addr", "127.0.0.1:8443",
		"-plaintext",
		"-cluster-id", testClusterID,
		"-node-name", testNodeName,
		"-ttl", "1m",
		"-interval", "1m",
	}, &stderr)
	if got := cli.ProcessExitCode(err); got != int(cli.ExitUsage) {
		t.Fatalf("exit code = %d, want %d", got, cli.ExitUsage)
	}
}

func TestUsageListsAgentCommands(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Execute(version.Info{Version: "test"}, []string{"help"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "bao-unseal-agent publish-once") {
		t.Fatalf("usage output = %q, want publish-once command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "bao-unseal-agent run") {
		t.Fatalf("usage output = %q, want run command", stdout.String())
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

func runExecuteCommand(args ...string) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	return Execute(version.Info{Version: "test"}, args, &stdout, &stderr)
}

func publishOptionsFixture() publishOnceOptions {
	return publishOnceOptions{
		address:    "127.0.0.1:8443",
		clusterID:  testClusterID,
		nodeName:   testNodeName,
		nodeUID:    testNodeUID,
		providerID: broker.NodeEvidenceProviderFakeLocal,
		ttl:        time.Minute,
		timeout:    time.Second,
		format:     testFormatJSON,
	}
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
