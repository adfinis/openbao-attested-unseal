package baounsealctl

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
)

type k8sEvidenceListOutput struct {
	ClusterID string                  `json:"cluster_id"`
	NodeName  string                  `json:"node_name,omitempty"`
	Count     int                     `json:"count"`
	Evidence  []k8sNodeEvidenceOutput `json:"evidence"`
	Decision  string                  `json:"decision"`
}

type k8sEvidenceInspectOutput struct {
	Evidence k8sNodeEvidenceOutput `json:"evidence"`
	Decision string                `json:"decision"`
}

func k8sEvidenceCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected k8s evidence subcommand"))
	}
	switch args[0] {
	case "list":
		return k8sEvidenceListCommand(args[1:], stdout, stderr)
	case "inspect":
		return k8sEvidenceInspectCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown k8s evidence subcommand %q", args[0]))
	}
}

func k8sEvidenceListCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseK8sEvidenceOptions("k8s evidence list", args, stderr, false)
	if err != nil {
		return err
	}
	out, err := listK8sNodeEvidence(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Node evidence records: %d\n", out.Count)
		_, _ = fmt.Fprintf(stdout, "Cluster: %s\n", out.ClusterID)
		for _, evidence := range out.Evidence {
			_, _ = fmt.Fprintf(
				stdout,
				"  %s provider=%s status=%s expires=%s\n",
				evidence.NodeName,
				evidence.ProviderID,
				evidence.Status,
				evidence.ExpiresAt,
			)
		}
		_, _ = fmt.Fprintf(stdout, "Decision: %s\n", out.Decision)
	})
}

func k8sEvidenceInspectCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseK8sEvidenceOptions("k8s evidence inspect", args, stderr, true)
	if err != nil {
		return err
	}
	out, err := inspectK8sNodeEvidence(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		evidence := out.Evidence
		_, _ = fmt.Fprintf(stdout, "Node evidence: %s\n", evidence.NodeName)
		_, _ = fmt.Fprintf(stdout, "Cluster: %s\n", evidence.ClusterID)
		if evidence.NodeUID != "" {
			_, _ = fmt.Fprintf(stdout, "Node UID: %s\n", evidence.NodeUID)
		}
		_, _ = fmt.Fprintf(stdout, "Provider: %s\n", evidence.ProviderID)
		_, _ = fmt.Fprintf(stdout, "Evidence hash: %s\n", evidence.EvidenceHash)
		_, _ = fmt.Fprintf(stdout, "Collected: %s\n", evidence.CollectedAt)
		_, _ = fmt.Fprintf(stdout, "Expires: %s\n", evidence.ExpiresAt)
		_, _ = fmt.Fprintf(stdout, "Status: %s\n", evidence.Status)
		_, _ = fmt.Fprintf(stdout, "Decision: %s\n", out.Decision)
	})
}

func parseK8sEvidenceOptions(
	name string,
	args []string,
	stderr io.Writer,
	requireNodeName bool,
) (k8sEvidenceOptions, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("addr", envOrDefault("BAO_UNSEALD_ADDR", "127.0.0.1:8443"), "bao-unseald gRPC address.")
	plaintext := flags.Bool("plaintext", false, "Use plaintext gRPC for local kind/lab deployments.")
	caCertPath := flags.String("ca-cert", "", "Optional PEM CA certificate for broker TLS.")
	tlsServerName := flags.String("tls-server-name", "", "Optional TLS server name override.")
	clientCertPath := flags.String("client-cert", "", "Optional PEM client certificate for broker mTLS.")
	clientKeyPath := flags.String("client-key", "", "Optional PEM client key for broker mTLS.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	nodeName := flags.String("node-name", "", "Optional Kubernetes node name filter.")
	timeout := flags.Duration("timeout", broker.DefaultKubernetesAPITimeout, "Broker request timeout.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return k8sEvidenceOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return k8sEvidenceOptions{}, err
	}
	if strings.TrimSpace(*address) == "" || strings.TrimSpace(*clusterID) == "" {
		return k8sEvidenceOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-addr and -cluster-id are required"))
	}
	if requireNodeName && strings.TrimSpace(*nodeName) == "" {
		return k8sEvidenceOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-node-name is required"))
	}
	if *timeout <= 0 {
		return k8sEvidenceOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	if (strings.TrimSpace(*clientCertPath) == "") != (strings.TrimSpace(*clientKeyPath) == "") {
		return k8sEvidenceOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-client-cert and -client-key must be provided together"),
		)
	}
	return k8sEvidenceOptions{
		address:        strings.TrimSpace(*address),
		plaintext:      *plaintext,
		caCertPath:     strings.TrimSpace(*caCertPath),
		tlsServerName:  strings.TrimSpace(*tlsServerName),
		clientCertPath: strings.TrimSpace(*clientCertPath),
		clientKeyPath:  strings.TrimSpace(*clientKeyPath),
		clusterID:      strings.TrimSpace(*clusterID),
		nodeName:       strings.TrimSpace(*nodeName),
		timeout:        *timeout,
		format:         *format,
	}, nil
}

func listK8sNodeEvidence(options k8sEvidenceOptions) (k8sEvidenceListOutput, error) {
	records, decision, err := fetchK8sNodeEvidence(options)
	if err != nil {
		return k8sEvidenceListOutput{}, err
	}
	return k8sEvidenceListOutput{
		ClusterID: options.clusterID,
		NodeName:  options.nodeName,
		Count:     len(records),
		Evidence:  records,
		Decision:  decision,
	}, nil
}

func inspectK8sNodeEvidence(options k8sEvidenceOptions) (k8sEvidenceInspectOutput, error) {
	records, decision, err := fetchK8sNodeEvidence(options)
	if err != nil {
		return k8sEvidenceInspectOutput{}, err
	}
	if len(records) != 1 {
		return k8sEvidenceInspectOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf("expected one node evidence record for %q, got %d", options.nodeName, len(records)),
		)
	}
	return k8sEvidenceInspectOutput{Evidence: records[0], Decision: decision}, nil
}

func fetchK8sNodeEvidence(options k8sEvidenceOptions) ([]k8sNodeEvidenceOutput, string, error) {
	dialOptions, err := brokerAdminDialOptions(k8sEvidenceAdminClientOptions(options))
	if err != nil {
		return nil, "", cli.WithExitCode(cli.ExitConfig, err)
	}
	conn, err := grpc.NewClient(options.address, dialOptions...)
	if err != nil {
		return nil, "", cli.WithExitCode(cli.ExitConfig, fmt.Errorf("create broker client: %w", err))
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	client := protocolv1.NewAdminServiceClient(conn)
	response, err := client.ListNodeEvidence(ctx, &protocolv1.NodeEvidenceListRequest{
		ClusterId: options.clusterID,
		NodeName:  options.nodeName,
	})
	if err != nil {
		return nil, "", cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("list node evidence: %w", err))
	}
	if err := requireAllowDecision(response.GetDecision(), "list node evidence"); err != nil {
		return nil, "", cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	records := make([]k8sNodeEvidenceOutput, 0, len(response.GetEvidence()))
	for _, evidence := range response.GetEvidence() {
		records = append(records, k8sNodeEvidenceOutputFromProto(evidence))
	}
	return records, policyDecisionOutput(response.GetDecision().GetState()), nil
}
