package baounsealctl

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
)

type k8sCheckOptions struct {
	k8sEvidenceOptions
	tokenFile string
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

type k8sWorkloadOutput struct {
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	PodName        string `json:"pod_name,omitempty"`
	PodUID         string `json:"pod_uid,omitempty"`
	NodeName       string `json:"node_name,omitempty"`
	NodeUID        string `json:"node_uid,omitempty"`
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

func availabilityOutput(available bool) string {
	if available {
		return "available"
	}
	return "unavailable"
}
