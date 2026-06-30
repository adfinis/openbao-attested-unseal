package baounsealctl

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	kubernetesProviderFakeLocal       = "fake-local"
	k8sDiagnosticNodeEvidence         = "node-evidence"
	k8sDiagnosticNodeWorkloadEvidence = "node-and-workload-evidence"
	k8sEvidenceStatusDenied           = "denied"
	k8sEvidenceStatusFresh            = "fresh"
	k8sEvidenceStatusInvalid          = "invalid"
	k8sEvidenceStatusMissing          = "missing"
	k8sEvidenceStatusStale            = "stale"
	k8sEvidenceStatusUnavailable      = "unavailable"
	k8sEvidenceStatusUnknown          = "unknown"
	k8sEvidenceStatusVerified         = "verified"
)

type k8sAdminClientOptions struct {
	address        string
	plaintext      bool
	caCertPath     string
	tlsServerName  string
	clientCertPath string
	clientKeyPath  string
	timeout        time.Duration
	format         string
}

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

type k8sCheckOptions struct {
	k8sEvidenceOptions
	tokenFile string
}

type k8sEvidenceOptions struct {
	address        string
	plaintext      bool
	caCertPath     string
	tlsServerName  string
	clientCertPath string
	clientKeyPath  string
	clusterID      string
	nodeName       string
	timeout        time.Duration
	format         string
}

type k8sCheckOutput struct {
	ClusterID       string                 `json:"cluster_id"`
	NodeName        string                 `json:"node_name"`
	Status          string                 `json:"status"`
	EvidenceStatus  string                 `json:"evidence_status"`
	WorkloadStatus  string                 `json:"workload_status,omitempty"`
	BrokerAdminAPI  bool                   `json:"broker_admin_api"`
	DiagnosticScope string                 `json:"diagnostic_scope"`
	Evidence        *k8sNodeEvidenceOutput `json:"evidence,omitempty"`
	Subject         string                 `json:"subject,omitempty"`
	Workload        *k8sWorkloadOutput     `json:"workload,omitempty"`
	Decision        string                 `json:"decision"`
	Message         string                 `json:"message,omitempty"`
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

type k8sNodeEvidenceOutput struct {
	ClusterID    string `json:"cluster_id"`
	NodeName     string `json:"node_name"`
	NodeUID      string `json:"node_uid,omitempty"`
	ProviderID   string `json:"provider_id"`
	EvidenceHash string `json:"evidence_hash"`
	CollectedAt  string `json:"collected_at"`
	ExpiresAt    string `json:"expires_at"`
	Status       string `json:"status"`
}

type k8sWorkloadOutput struct {
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	PodName        string `json:"pod_name,omitempty"`
	PodUID         string `json:"pod_uid,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	NodeUID        string `json:"node_uid,omitempty"`
}

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

func k8sCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected k8s subcommand"))
	}
	switch args[0] {
	case "check":
		return k8sCheckCommand(args[1:], stdout, stderr)
	case "evidence":
		return k8sEvidenceCommand(args[1:], stdout, stderr)
	case "publish-node":
		return k8sPublishNodeCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown k8s subcommand %q", args[0]))
	}
}

func k8sCheckCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseK8sCheckOptions(args, stderr)
	if err != nil {
		return err
	}
	out, checkErr, err := checkK8sNodeEvidence(options)
	if err != nil {
		return err
	}
	if err := writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Kubernetes check: %s\n", out.Status)
		_, _ = fmt.Fprintf(stdout, "Cluster: %s\n", out.ClusterID)
		_, _ = fmt.Fprintf(stdout, "Node: %s\n", out.NodeName)
		_, _ = fmt.Fprintf(stdout, "Broker admin API: %s\n", availabilityOutput(out.BrokerAdminAPI))
		_, _ = fmt.Fprintf(stdout, "Evidence status: %s\n", out.EvidenceStatus)
		if out.WorkloadStatus != "" {
			_, _ = fmt.Fprintf(stdout, "Workload status: %s\n", out.WorkloadStatus)
		}
		if out.Evidence != nil {
			_, _ = fmt.Fprintf(stdout, "Provider: %s\n", out.Evidence.ProviderID)
			_, _ = fmt.Fprintf(stdout, "Evidence hash: %s\n", out.Evidence.EvidenceHash)
			_, _ = fmt.Fprintf(stdout, "Collected: %s\n", out.Evidence.CollectedAt)
			_, _ = fmt.Fprintf(stdout, "Expires: %s\n", out.Evidence.ExpiresAt)
		}
		if out.Subject != "" {
			_, _ = fmt.Fprintf(stdout, "Subject: %s\n", out.Subject)
		}
		if out.Workload != nil {
			_, _ = fmt.Fprintf(stdout, "Namespace: %s\n", out.Workload.Namespace)
			_, _ = fmt.Fprintf(stdout, "Service account: %s\n", out.Workload.ServiceAccount)
			_, _ = fmt.Fprintf(stdout, "Pod: %s\n", out.Workload.PodName)
		}
		if out.Message != "" {
			_, _ = fmt.Fprintf(stdout, "Message: %s\n", out.Message)
		}
		_, _ = fmt.Fprintf(stdout, "Decision: %s\n", out.Decision)
	}); err != nil {
		return err
	}
	return checkErr
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

	now := time.Now().UTC()
	evidenceHash := options.evidenceHash
	if evidenceHash == "" {
		evidenceHash = defaultK8sEvidenceHash(options)
	}
	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	client := protocolv1.NewAdminServiceClient(conn)
	response, err := client.PublishNodeEvidence(ctx, &protocolv1.NodeEvidencePublishRequest{
		Evidence: &protocolv1.NodeEvidenceRecord{
			ClusterId:            options.clusterID,
			NodeName:             options.nodeName,
			NodeUid:              options.nodeUID,
			ProviderId:           options.providerID,
			EvidenceHash:         evidenceHash,
			CollectedUnixSeconds: now.Unix(),
			ExpiresUnixSeconds:   now.Add(options.ttl).Unix(),
		},
	})
	if err != nil {
		return k8sPublishNodeOutput{}, cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("publish node evidence: %w", err))
	}
	if err := requireAllowDecision(response.GetDecision(), "publish node evidence"); err != nil {
		return k8sPublishNodeOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	return k8sPublishNodeOutputFromProto(response.GetEvidence(), response.GetDecision()), nil
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

func parseK8sCheckOptions(args []string, stderr io.Writer) (k8sCheckOptions, error) {
	flags := flag.NewFlagSet("k8s check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("addr", envOrDefault("BAO_UNSEALD_ADDR", "127.0.0.1:8443"), "bao-unseald gRPC address.")
	plaintext := flags.Bool("plaintext", false, "Use plaintext gRPC for local kind/lab deployments.")
	caCertPath := flags.String("ca-cert", "", "Optional PEM CA certificate for broker TLS.")
	tlsServerName := flags.String("tls-server-name", "", "Optional TLS server name override.")
	clientCertPath := flags.String("client-cert", "", "Optional PEM client certificate for broker mTLS.")
	clientKeyPath := flags.String("client-key", "", "Optional PEM client key for broker mTLS.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	nodeName := flags.String("node-name", "", "Kubernetes node name.")
	tokenFile := flags.String(
		"token-file",
		"",
		"Optional Kubernetes workload token file for broker-side evidence diagnostics.",
	)
	timeout := flags.Duration("timeout", broker.DefaultKubernetesAPITimeout, "Broker request timeout.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return k8sCheckOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return k8sCheckOptions{}, err
	}
	if strings.TrimSpace(*address) == "" ||
		strings.TrimSpace(*clusterID) == "" ||
		strings.TrimSpace(*nodeName) == "" {
		return k8sCheckOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-addr, -cluster-id, and -node-name are required"),
		)
	}
	if *timeout <= 0 {
		return k8sCheckOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	if (strings.TrimSpace(*clientCertPath) == "") != (strings.TrimSpace(*clientKeyPath) == "") {
		return k8sCheckOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-client-cert and -client-key must be provided together"),
		)
	}
	return k8sCheckOptions{
		k8sEvidenceOptions: k8sEvidenceOptions{
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
		},
		tokenFile: strings.TrimSpace(*tokenFile),
	}, nil
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

func checkK8sNodeEvidence(options k8sCheckOptions) (k8sCheckOutput, error, error) {
	out := k8sCheckOutput{
		ClusterID:       options.clusterID,
		NodeName:        options.nodeName,
		Status:          k8sEvidenceStatusUnavailable,
		EvidenceStatus:  k8sEvidenceStatusUnknown,
		BrokerAdminAPI:  false,
		Decision:        k8sEvidenceStatusUnknown,
		DiagnosticScope: k8sDiagnosticNodeEvidence,
	}
	dialOptions, err := brokerAdminDialOptions(k8sEvidenceAdminClientOptions(options.k8sEvidenceOptions))
	if err != nil {
		return k8sCheckOutput{}, nil, cli.WithExitCode(cli.ExitConfig, err)
	}
	conn, err := grpc.NewClient(options.address, dialOptions...)
	if err != nil {
		return k8sCheckOutput{}, nil, cli.WithExitCode(cli.ExitConfig, fmt.Errorf("create broker client: %w", err))
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	client := protocolv1.NewAdminServiceClient(conn)
	status, err := client.Status(ctx, &protocolv1.AdminStatusRequest{})
	if err != nil {
		return k8sCheckOutput{}, nil, cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("read broker admin status: %w", err))
	}
	out.BrokerAdminAPI = status.GetImplemented()
	if !status.GetImplemented() {
		out.Message = status.GetMessage()
		return out, cli.WithExitCode(cli.ExitCheckFailed, errors.New("broker admin node evidence API is unavailable")), nil
	}

	response, err := client.ListNodeEvidence(ctx, &protocolv1.NodeEvidenceListRequest{
		ClusterId: options.clusterID,
		NodeName:  options.nodeName,
	})
	if err != nil {
		return k8sCheckOutput{}, nil, cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("list node evidence: %w", err))
	}
	out.Decision = policyDecisionOutput(response.GetDecision().GetState())
	if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		out.Status = k8sCheckStatusFromDecision(response.GetDecision())
		out.EvidenceStatus = out.Status
		out.Message = policyDecisionMessage(response.GetDecision(), "broker denied node evidence lookup")
		return out, cli.WithExitCode(cli.ExitCheckFailed, errors.New(out.Message)), nil
	}
	if len(response.GetEvidence()) != 1 {
		out.Status = k8sEvidenceStatusMissing
		out.EvidenceStatus = k8sEvidenceStatusMissing
		out.Message = fmt.Sprintf(
			"expected one node evidence record for %q, got %d",
			options.nodeName,
			len(response.GetEvidence()),
		)
		return out, cli.WithExitCode(cli.ExitCheckFailed, errors.New(out.Message)), nil
	}
	evidence := k8sNodeEvidenceOutputFromProto(response.GetEvidence()[0])
	out.Evidence = &evidence
	out.EvidenceStatus = evidence.Status
	switch evidence.Status {
	case k8sEvidenceStatusFresh:
		out.Status = k8sEvidenceStatusFresh
		if options.tokenFile == "" {
			return out, nil, nil
		}
	case k8sEvidenceStatusStale:
		out.Status = k8sEvidenceStatusStale
		out.Message = "node evidence is stale"
		return out, cli.WithExitCode(cli.ExitCheckFailed, errors.New(out.Message)), nil
	default:
		out.Status = evidence.Status
		out.Message = "node evidence is not fresh"
		return out, cli.WithExitCode(cli.ExitCheckFailed, errors.New(out.Message)), nil
	}
	if err := checkK8sWorkloadEvidence(ctx, client, options, &out); err != nil {
		return out, err, nil
	}
	return out, nil, nil
}

func checkK8sWorkloadEvidence(
	ctx context.Context,
	client protocolv1.AdminServiceClient,
	options k8sCheckOptions,
	out *k8sCheckOutput,
) error {
	out.DiagnosticScope = k8sDiagnosticNodeWorkloadEvidence
	out.WorkloadStatus = k8sEvidenceStatusUnavailable
	token, err := readK8sWorkloadTokenFile(options.tokenFile)
	if err != nil {
		out.Status = k8sEvidenceStatusInvalid
		out.WorkloadStatus = k8sEvidenceStatusInvalid
		out.Message = err.Error()
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	evidence, err := k8sprovider.NewEvidenceEnvelope("", token)
	if err != nil {
		out.Status = k8sEvidenceStatusInvalid
		out.WorkloadStatus = k8sEvidenceStatusInvalid
		out.Message = err.Error()
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	response, err := client.CheckEvidence(ctx, &protocolv1.EvidenceCheckRequest{
		ClusterId: options.clusterID,
		Operation: protocolv1.Operation_OPERATION_WRAP,
		Evidence:  evidence,
	})
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("check workload evidence: %w", err))
	}
	out.Decision = policyDecisionOutput(response.GetDecision().GetState())
	out.Subject = response.GetSubject()
	out.Workload = k8sWorkloadOutputFromProto(response.GetWorkload())
	if response.GetNodeEvidence() != nil {
		nodeEvidence := k8sNodeEvidenceOutputFromProto(response.GetNodeEvidence())
		out.Evidence = &nodeEvidence
		out.EvidenceStatus = nodeEvidence.Status
	}
	if response.GetDecision().GetState() == protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		out.Status = k8sEvidenceStatusVerified
		out.WorkloadStatus = k8sEvidenceStatusVerified
		return nil
	}
	out.Status = k8sWorkloadStatusFromDecision(response.GetDecision())
	out.WorkloadStatus = out.Status
	out.Message = policyDecisionMessage(response.GetDecision(), "broker denied workload evidence check")
	return cli.WithExitCode(cli.ExitCheckFailed, errors.New(out.Message))
}

func readK8sWorkloadTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("-token-file is required for workload evidence diagnostics")
	}
	// #nosec G304 -- Kubernetes workload token path is operator supplied.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read Kubernetes workload token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("kubernetes workload token file is empty")
	}
	return token, nil
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

func k8sEvidenceAdminClientOptions(options k8sEvidenceOptions) k8sAdminClientOptions {
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

func brokerAdminDialOptions(options k8sAdminClientOptions) ([]grpc.DialOption, error) {
	if options.plaintext {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: options.tlsServerName,
	}
	if options.caCertPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		// #nosec G304 -- broker CA path is operator supplied.
		caPEM, err := os.ReadFile(options.caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read broker CA certificate: %w", err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("broker CA certificate did not contain a PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if options.clientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(options.clientCertPath, options.clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load broker client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}

func requireAllowDecision(decision *protocolv1.PolicyDecision, operation string) error {
	if decision.GetState() == protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		return nil
	}
	messages := policyDecisionMessages(decision)
	if len(messages) == 0 {
		return fmt.Errorf("broker denied %s", operation)
	}
	return fmt.Errorf("broker denied %s: %s", operation, strings.Join(messages, "; "))
}

func policyDecisionMessages(decision *protocolv1.PolicyDecision) []string {
	messages := make([]string, 0, len(decision.GetErrors()))
	for _, brokerErr := range decision.GetErrors() {
		if brokerErr.GetMessage() != "" {
			messages = append(messages, brokerErr.GetMessage())
		}
	}
	return messages
}

func policyDecisionMessage(decision *protocolv1.PolicyDecision, fallback string) string {
	messages := policyDecisionMessages(decision)
	if len(messages) == 0 {
		return fallback
	}
	return strings.Join(messages, "; ")
}

func k8sCheckStatusFromDecision(decision *protocolv1.PolicyDecision) string {
	for _, brokerErr := range decision.GetErrors() {
		switch brokerErr.GetCode() {
		case protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED:
			return k8sEvidenceStatusMissing
		case protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST:
			return k8sEvidenceStatusInvalid
		case protocolv1.ErrorCode_ERROR_CODE_INTERNAL:
			return k8sEvidenceStatusUnavailable
		default:
		}
	}
	return k8sEvidenceStatusDenied
}

func k8sWorkloadStatusFromDecision(decision *protocolv1.PolicyDecision) string {
	for _, brokerErr := range decision.GetErrors() {
		switch brokerErr.GetCode() {
		case protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED,
			protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
			protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST:
			return k8sEvidenceStatusInvalid
		case protocolv1.ErrorCode_ERROR_CODE_BROKER_UNAVAILABLE,
			protocolv1.ErrorCode_ERROR_CODE_INTERNAL:
			return k8sEvidenceStatusUnavailable
		case protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED:
			return k8sEvidenceStatusDenied
		default:
		}
	}
	return k8sEvidenceStatusDenied
}

func availabilityOutput(available bool) string {
	if available {
		return "available"
	}
	return "unavailable"
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

func k8sNodeEvidenceOutputFromProto(evidence *protocolv1.NodeEvidenceRecord) k8sNodeEvidenceOutput {
	return k8sNodeEvidenceOutput{
		ClusterID:    evidence.GetClusterId(),
		NodeName:     evidence.GetNodeName(),
		NodeUID:      evidence.GetNodeUid(),
		ProviderID:   evidence.GetProviderId(),
		EvidenceHash: evidence.GetEvidenceHash(),
		CollectedAt:  unixSecondsOutput(evidence.GetCollectedUnixSeconds()),
		ExpiresAt:    unixSecondsOutput(evidence.GetExpiresUnixSeconds()),
		Status:       nodeEvidenceStatusOutput(evidence.GetStatus()),
	}
}

func k8sWorkloadOutputFromProto(workload *protocolv1.WorkloadIdentity) *k8sWorkloadOutput {
	if workload == nil {
		return nil
	}
	return &k8sWorkloadOutput{
		Namespace:      workload.GetNamespace(),
		ServiceAccount: workload.GetServiceAccount(),
		PodName:        workload.GetPodName(),
		PodUID:         workload.GetPodUid(),
		NodeName:       workload.GetNodeName(),
		NodeUID:        workload.GetNodeUid(),
	}
}

func unixSecondsOutput(value int64) string {
	if value <= 0 {
		return ""
	}
	return time.Unix(value, 0).UTC().Format(time.RFC3339)
}

func nodeEvidenceStatusOutput(status protocolv1.NodeEvidenceStatus) string {
	switch status {
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_FRESH:
		return k8sEvidenceStatusFresh
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_STALE:
		return k8sEvidenceStatusStale
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_MISSING:
		return k8sEvidenceStatusMissing
	case protocolv1.NodeEvidenceStatus_NODE_EVIDENCE_STATUS_INVALID:
		return k8sEvidenceStatusInvalid
	default:
		return "unspecified"
	}
}

func policyDecisionOutput(state protocolv1.PolicyDecisionState) string {
	switch state {
	case protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW:
		return "allow"
	case protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY:
		return "deny"
	default:
		return "unspecified"
	}
}
