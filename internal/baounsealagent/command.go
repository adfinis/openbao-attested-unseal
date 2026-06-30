// Package baounsealagent implements the node-local unseal evidence agent.
package baounsealagent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/brokeradmin"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/config"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeagent"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
	"google.golang.org/grpc"
)

const (
	formatText = "text"
	formatJSON = "json"
)

type publishOnceOptions struct {
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
	ttl            time.Duration
	timeout        time.Duration
	format         string
}

type publishOnceOutput struct {
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

// Execute runs bao-unseal-agent.
func Execute(info version.Info, args []string, stdout io.Writer, stderr io.Writer) error {
	if stdout == nil || stderr == nil {
		return cli.WithExitCode(cli.ExitUsage, errors.New("stdout and stderr writers are required"))
	}
	if len(args) == 0 {
		printUsage(stdout)
		return nil
	}
	switch args[0] {
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	case "version":
		printVersion(stdout, info)
		return nil
	case "publish-once":
		return publishOnceCommand(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown command %q", args[0]))
	}
}

func publishOnceCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parsePublishOnceOptions(args, stderr)
	if err != nil {
		return err
	}
	out, err := publishOnce(options)
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

func parsePublishOnceOptions(args []string, stderr io.Writer) (publishOnceOptions, error) {
	flags := flag.NewFlagSet("publish-once", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("addr", config.EnvOrDefault("BAO_UNSEALD_ADDR", "127.0.0.1:8443"), "bao-unseald gRPC address.")
	plaintext := flags.Bool("plaintext", false, "Use plaintext gRPC for local kind/lab deployments.")
	caCertPath := flags.String("ca-cert", "", "Optional PEM CA certificate for broker TLS.")
	tlsServerName := flags.String("tls-server-name", "", "Optional TLS server name override.")
	clientCertPath := flags.String("client-cert", "", "Optional PEM client certificate for broker mTLS.")
	clientKeyPath := flags.String("client-key", "", "Optional PEM client key for broker mTLS.")
	clusterID := flags.String(
		"cluster-id",
		config.EnvOrDefault("BAO_UNSEAL_CLUSTER_ID", "prod-eu1"),
		"Cluster identifier.",
	)
	nodeName := flags.String("node-name", config.EnvOrDefault("NODE_NAME", ""), "Kubernetes node name.")
	nodeUID := flags.String("node-uid", config.EnvOrDefault("NODE_UID", ""), "Optional Kubernetes node UID.")
	providerID := flags.String("provider-id", broker.NodeEvidenceProviderFakeLocal, "Node evidence provider identifier.")
	ttl := flags.Duration("ttl", broker.DefaultKubernetesNodeEvidenceTTL, "Node evidence TTL.")
	timeout := flags.Duration("timeout", broker.DefaultKubernetesAPITimeout, "Broker request timeout.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return publishOnceOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return publishOnceOptions{}, err
	}
	if strings.TrimSpace(*address) == "" ||
		strings.TrimSpace(*clusterID) == "" ||
		strings.TrimSpace(*nodeName) == "" {
		return publishOnceOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-addr, -cluster-id, and -node-name are required"),
		)
	}
	if strings.TrimSpace(*providerID) != broker.NodeEvidenceProviderFakeLocal {
		return publishOnceOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			fmt.Errorf("unsupported node evidence provider %q", *providerID),
		)
	}
	if *ttl <= 0 {
		return publishOnceOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-ttl must be greater than zero"))
	}
	if *timeout <= 0 {
		return publishOnceOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	if (strings.TrimSpace(*clientCertPath) == "") != (strings.TrimSpace(*clientKeyPath) == "") {
		return publishOnceOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-client-cert and -client-key must be provided together"),
		)
	}
	return publishOnceOptions{
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
		ttl:            *ttl,
		timeout:        *timeout,
		format:         *format,
	}, nil
}

func publishOnce(options publishOnceOptions) (publishOnceOutput, error) {
	dialOptions, err := brokeradmin.DialOptions(brokeradmin.ClientOptions{
		Plaintext:      options.plaintext,
		CACertPath:     options.caCertPath,
		TLSServerName:  options.tlsServerName,
		ClientCertPath: options.clientCertPath,
		ClientKeyPath:  options.clientKeyPath,
	})
	if err != nil {
		return publishOnceOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	conn, err := grpc.NewClient(options.address, dialOptions...)
	if err != nil {
		return publishOnceOutput{}, cli.WithExitCode(cli.ExitConfig, fmt.Errorf("create broker client: %w", err))
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	writer := &brokeradmin.NodeEvidenceWriter{
		Client: protocolv1.NewAdminServiceClient(conn),
	}
	provider, err := publishOnceProvider(options.providerID)
	if err != nil {
		return publishOnceOutput{}, err
	}
	publisher := nodeagent.Publisher{
		Writer:   writer,
		Provider: provider,
	}
	_, err = publisher.Publish(ctx, nodeagent.PublishRequest{
		ClusterID: options.clusterID,
		NodeName:  options.nodeName,
		NodeUID:   options.nodeUID,
		TTL:       options.ttl,
	})
	if err != nil {
		return publishOnceOutput{}, publishOnceExitError(err)
	}
	return publishOnceOutputFromProto(writer.Evidence, writer.Decision), nil
}

func publishOnceProvider(providerID string) (nodeagent.Provider, error) {
	switch providerID {
	case broker.NodeEvidenceProviderFakeLocal:
		return nodeagent.FakeLocalProvider{}, nil
	default:
		return nil, cli.WithExitCode(
			cli.ExitUsage,
			fmt.Errorf("unsupported node evidence provider %q", providerID),
		)
	}
}

func publishOnceExitError(err error) error {
	var denied brokeradmin.DecisionDeniedError
	if errors.As(err, &denied) {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if errors.Is(err, brokeradmin.ErrPublishNodeEvidence) {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	return err
}

func publishOnceOutputFromProto(
	evidence *protocolv1.NodeEvidenceRecord,
	decision *protocolv1.PolicyDecision,
) publishOnceOutput {
	return publishOnceOutput{
		ClusterID:    evidence.GetClusterId(),
		NodeName:     evidence.GetNodeName(),
		NodeUID:      evidence.GetNodeUid(),
		ProviderID:   evidence.GetProviderId(),
		EvidenceHash: evidence.GetEvidenceHash(),
		CollectedAt:  brokeradmin.UnixSecondsOutput(evidence.GetCollectedUnixSeconds()),
		ExpiresAt:    brokeradmin.UnixSecondsOutput(evidence.GetExpiresUnixSeconds()),
		Status:       brokeradmin.NodeEvidenceStatusOutput(evidence.GetStatus()),
		Decision:     brokeradmin.PolicyDecisionOutput(decision.GetState()),
	}
}

func validateFormat(format string) error {
	switch format {
	case formatText, formatJSON:
		return nil
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported format %q", format))
	}
}

//nolint:forbidigo // JSON output is a reviewed CLI serialization boundary for typed command DTOs.
func writeOutput[T any](stdout io.Writer, format string, value T, writeText func()) error {
	if format == formatJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	writeText()
	return nil
}

func printUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, "Node-local attested unseal evidence agent.")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Usage:")
	_, _ = fmt.Fprintln(out, "  bao-unseal-agent help")
	_, _ = fmt.Fprintln(out, "  bao-unseal-agent version")
	_, _ = fmt.Fprintln(out, "  bao-unseal-agent publish-once -cluster-id prod-eu1 -node-name kind-worker")
}

func printVersion(out io.Writer, info version.Info) {
	_, _ = fmt.Fprintf(out, "version: %s\n", info.Version)
	_, _ = fmt.Fprintf(out, "commit: %s\n", info.Commit)
	_, _ = fmt.Fprintf(out, "buildDate: %s\n", info.BuildDate)
	_, _ = fmt.Fprintf(out, "dirty: %s\n", info.Dirty)
}
