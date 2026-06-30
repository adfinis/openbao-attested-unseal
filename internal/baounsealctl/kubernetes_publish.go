package baounsealctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/brokeradmin"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeagent"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
)

type k8sPublishNodeOptions struct {
	address        string
	plaintext      bool
	caCertPath     string
	tlsServerName  string
	clientCertPath string
	clientKeyPath  string
	clusterID      string
	nodeName       string
	nodeUID        string
	providerID     string
	evidenceHash   string
	ttl            time.Duration
	timeout        time.Duration
	format         string
}

type k8sPublishNodeOutput struct {
	ClusterID    string `json:"cluster_id"`
	NodeName     string `json:"node_name"`
	NodeUID      string `json:"node_uid,omitempty"`
	ProviderID   string `json:"provider_id"`
	EvidenceHash string `json:"evidence_hash"`
	CollectedAt  string `json:"collected_at"`
	ExpiresAt    string `json:"expires_at"`
	Status       string `json:"status"`
	Decision     string `json:"decision"`
}

func k8sPublishNodeCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseK8sPublishNodeOptions(args, stderr)
	if err != nil {
		return err
	}
	out, err := publishK8sNodeEvidence(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Published node evidence for %s\n", out.NodeName)
		_, _ = fmt.Fprintf(stdout, "Cluster: %s\n", out.ClusterID)
		_, _ = fmt.Fprintf(stdout, "Provider: %s\n", out.ProviderID)
		_, _ = fmt.Fprintf(stdout, "Status: %s\n", out.Status)
		_, _ = fmt.Fprintf(stdout, "Decision: %s\n", out.Decision)
	})
}

func parseK8sPublishNodeOptions(args []string, stderr io.Writer) (k8sPublishNodeOptions, error) {
	flags := flag.NewFlagSet("k8s publish-node", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("addr", envOrDefault("BAO_UNSEALD_ADDR", "127.0.0.1:8443"), "bao-unseald gRPC address.")
	plaintext := flags.Bool("plaintext", false, "Use plaintext gRPC for local kind/lab deployments.")
	caCertPath := flags.String("ca-cert", "", "Optional PEM CA certificate for broker TLS.")
	tlsServerName := flags.String("tls-server-name", "", "Optional TLS server name override.")
	clientCertPath := flags.String("client-cert", "", "Optional PEM client certificate for broker mTLS.")
	clientKeyPath := flags.String("client-key", "", "Optional PEM client key for broker mTLS.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	nodeName := flags.String("node-name", "", "Kubernetes node name.")
	nodeUID := flags.String("node-uid", "", "Optional Kubernetes node UID.")
	providerID := flags.String("provider-id", kubernetesProviderFakeLocal, "Node evidence provider identifier.")
	evidenceHash := flags.String("evidence-hash", "", "Optional synthetic evidence hash.")
	ttl := flags.Duration("ttl", broker.DefaultKubernetesNodeEvidenceTTL, "Node evidence TTL.")
	timeout := flags.Duration("timeout", broker.DefaultKubernetesAPITimeout, "Broker request timeout.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return k8sPublishNodeOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return k8sPublishNodeOptions{}, err
	}
	if strings.TrimSpace(*address) == "" ||
		strings.TrimSpace(*clusterID) == "" ||
		strings.TrimSpace(*nodeName) == "" {
		return k8sPublishNodeOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-addr, -cluster-id, and -node-name are required"),
		)
	}
	if strings.TrimSpace(*providerID) == "" {
		return k8sPublishNodeOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-provider-id is required"))
	}
	if *ttl <= 0 {
		return k8sPublishNodeOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-ttl must be greater than zero"))
	}
	if *timeout <= 0 {
		return k8sPublishNodeOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	if (strings.TrimSpace(*clientCertPath) == "") != (strings.TrimSpace(*clientKeyPath) == "") {
		return k8sPublishNodeOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-client-cert and -client-key must be provided together"),
		)
	}
	return k8sPublishNodeOptions{
		address:        strings.TrimSpace(*address),
		plaintext:      *plaintext,
		caCertPath:     strings.TrimSpace(*caCertPath),
		tlsServerName:  strings.TrimSpace(*tlsServerName),
		clientCertPath: strings.TrimSpace(*clientCertPath),
		clientKeyPath:  strings.TrimSpace(*clientKeyPath),
		clusterID:      strings.TrimSpace(*clusterID),
		nodeName:       strings.TrimSpace(*nodeName),
		nodeUID:        strings.TrimSpace(*nodeUID),
		providerID:     strings.TrimSpace(*providerID),
		evidenceHash:   strings.TrimSpace(*evidenceHash),
		ttl:            *ttl,
		timeout:        *timeout,
		format:         *format,
	}, nil
}

func publishK8sNodeEvidence(options k8sPublishNodeOptions) (k8sPublishNodeOutput, error) {
	dialOptions, err := brokerAdminDialOptions(k8sPublishAdminClientOptions(options))
	if err != nil {
		return k8sPublishNodeOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	conn, err := grpc.NewClient(options.address, dialOptions...)
	if err != nil {
		return k8sPublishNodeOutput{}, cli.WithExitCode(cli.ExitConfig, fmt.Errorf("create broker client: %w", err))
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	client := protocolv1.NewAdminServiceClient(conn)
	writer := &brokeradmin.NodeEvidenceWriter{Client: client}
	publisher := nodeagent.Publisher{
		Writer:   writer,
		Provider: k8sPublishNodeProvider(options),
	}
	_, err = publisher.Publish(ctx, nodeagent.PublishRequest{
		ClusterID: options.clusterID,
		NodeName:  options.nodeName,
		NodeUID:   options.nodeUID,
		TTL:       options.ttl,
	})
	if err != nil {
		return k8sPublishNodeOutput{}, k8sPublishNodeExitError(err)
	}
	return k8sPublishNodeOutputFromProto(writer.Evidence, writer.Decision), nil
}

func k8sPublishNodeExitError(err error) error {
	var denied brokeradmin.DecisionDeniedError
	if errors.As(err, &denied) {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if errors.Is(err, brokeradmin.ErrPublishNodeEvidence) {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	return err
}

func k8sPublishNodeProvider(options k8sPublishNodeOptions) nodeagent.Provider {
	if options.providerID == broker.NodeEvidenceProviderFakeLocal && options.evidenceHash == "" {
		return nodeagent.FakeLocalProvider{}
	}
	evidenceHash := options.evidenceHash
	if evidenceHash == "" {
		evidenceHash = defaultK8sEvidenceHash(options)
	}
	return staticNodeEvidenceProvider{
		evidence: nodeagent.ProviderEvidence{
			ProviderID:   options.providerID,
			EvidenceHash: evidenceHash,
		},
	}
}

type staticNodeEvidenceProvider struct {
	evidence nodeagent.ProviderEvidence
}

func (p staticNodeEvidenceProvider) CollectNodeEvidence(
	context.Context,
	nodeagent.PublishRequest,
) (nodeagent.ProviderEvidence, error) {
	return p.evidence, nil
}

func k8sPublishAdminClientOptions(options k8sPublishNodeOptions) k8sAdminClientOptions {
	return k8sAdminClientOptions{
		address:        options.address,
		plaintext:      options.plaintext,
		caCertPath:     options.caCertPath,
		tlsServerName:  options.tlsServerName,
		clientCertPath: options.clientCertPath,
		clientKeyPath:  options.clientKeyPath,
		timeout:        options.timeout,
		format:         options.format,
	}
}

func defaultK8sEvidenceHash(options k8sPublishNodeOptions) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		options.clusterID,
		options.nodeName,
		options.nodeUID,
		options.providerID,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func k8sPublishNodeOutputFromProto(
	evidence *protocolv1.NodeEvidenceRecord,
	decision *protocolv1.PolicyDecision,
) k8sPublishNodeOutput {
	record := k8sNodeEvidenceOutputFromProto(evidence)
	return k8sPublishNodeOutput{
		ClusterID:    record.ClusterID,
		NodeName:     record.NodeName,
		NodeUID:      record.NodeUID,
		ProviderID:   record.ProviderID,
		EvidenceHash: record.EvidenceHash,
		CollectedAt:  record.CollectedAt,
		ExpiresAt:    record.ExpiresAt,
		Status:       record.Status,
		Decision:     policyDecisionOutput(decision.GetState()),
	}
}
