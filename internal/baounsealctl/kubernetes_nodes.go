package baounsealctl

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/brokeradmin"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
	"google.golang.org/grpc"
)

type k8sNodeControlOptions struct {
	address        string
	caCertPath     string
	tlsServerName  string
	clientCertPath string
	clientKeyPath  string
	clusterID      string
	nodeName       string
	timeout        time.Duration
	format         string
}

type k8sNodeEnrollmentOutput struct {
	RequestID                  string   `json:"request_id"`
	ClusterID                  string   `json:"cluster_id"`
	NodeName                   string   `json:"node_name"`
	NodeUID                    string   `json:"node_uid"`
	ProviderID                 string   `json:"provider_id"`
	PolicyMode                 string   `json:"policy_mode"`
	EnrolledAKPublicHash       string   `json:"enrolled_ak_public_hash"`
	PublisherCertificateSHA256 []string `json:"publisher_certificate_sha256"`
	Revision                   uint64   `json:"revision"`
	EnrolledAt                 string   `json:"enrolled_at"`
	UpdatedAt                  string   `json:"updated_at"`
	RevokedAt                  string   `json:"revoked_at,omitempty"`
	Status                     string   `json:"status"`
}

func k8sNodesCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected k8s nodes subcommand"))
	}
	switch args[0] {
	case commandEnroll:
		return k8sNodesEnrollCommand(args[1:], stdout, stderr)
	case "revoke":
		return k8sNodesRevokeCommand(args[1:], stdout, stderr)
	case "list":
		return k8sNodesListCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown k8s nodes subcommand %q", args[0]))
	}
}

func k8sNodesEnrollCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("k8s nodes enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := addK8sNodeControlFlags(flags, true)
	nodeUID := flags.String("node-uid", "", "Kubernetes node UID.")
	policyPath := flags.String("tpm-policy", "", "Path to the approved TPM policy JSON.")
	publisherHashes := flags.String(
		"publisher-cert-sha256",
		"",
		"Comma-separated SHA-256 hashes of authorized publisher certificates.",
	)
	reason := flags.String("reason", "", "Required audit reason or change reference.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	options, err := common.options()
	if err != nil {
		return err
	}
	if strings.TrimSpace(*nodeUID) == "" || strings.TrimSpace(*policyPath) == "" ||
		strings.TrimSpace(*reason) == "" {
		return cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-node-uid, -tpm-policy, and -reason are required"),
		)
	}
	hashes, err := parseCertificateHashes(*publisherHashes)
	if err != nil {
		return err
	}
	var policy tpmlocal.Policy
	if err := readJSONFile(strings.TrimSpace(*policyPath), &policy); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	requestID, err := randomID("request")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	enrollmentRequest, err := nodeevidence.NormalizeEnrollmentRequest(nodeevidence.EnrollmentRequest{
		ClusterID:                  options.clusterID,
		NodeName:                   options.nodeName,
		NodeUID:                    strings.TrimSpace(*nodeUID),
		Provider:                   nodeevidence.ProviderTPM2Quote,
		TPMPolicy:                  policy,
		PublisherCertificateHashes: hashes,
		EnrolledAt:                 time.Now().UTC(),
	})
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	client, closeClient, err := newK8sNodeEnrollmentClient(options)
	if err != nil {
		return err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	enrollment, err := client.Enroll(
		ctx,
		enrollmentRequest,
		strings.TrimSpace(*reason),
		&protocolv1.AuditContext{RequestId: requestID},
	)
	if err != nil {
		return k8sNodeControlExitError(err)
	}
	out := k8sNodeEnrollmentOutputFromDomain(enrollment, requestID)
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Enrolled node evidence trust for %s\n", out.NodeName)
		_, _ = fmt.Fprintf(stdout, "Revision: %d\n", out.Revision)
		_, _ = fmt.Fprintf(stdout, "Request ID: %s\n", out.RequestID)
	})
}

func k8sNodesRevokeCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("k8s nodes revoke", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := addK8sNodeControlFlags(flags, true)
	reason := flags.String("reason", "", "Required audit reason or change reference.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	options, err := common.options()
	if err != nil {
		return err
	}
	if strings.TrimSpace(*reason) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-reason is required"))
	}
	requestID, err := randomID("request")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	client, closeClient, err := newK8sNodeEnrollmentClient(options)
	if err != nil {
		return err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	enrollment, err := client.Revoke(
		ctx,
		options.clusterID,
		options.nodeName,
		strings.TrimSpace(*reason),
		&protocolv1.AuditContext{RequestId: requestID},
	)
	if err != nil {
		return k8sNodeControlExitError(err)
	}
	out := k8sNodeEnrollmentOutputFromDomain(enrollment, requestID)
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Revoked node evidence trust for %s\n", out.NodeName)
		_, _ = fmt.Fprintf(stdout, "Revision: %d\n", out.Revision)
		_, _ = fmt.Fprintf(stdout, "Request ID: %s\n", out.RequestID)
	})
}

func k8sNodesListCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("k8s nodes list", flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := addK8sNodeControlFlags(flags, false)
	includeRevoked := flags.Bool("include-revoked", false, "Include revoked node trust records.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	options, err := common.options()
	if err != nil {
		return err
	}
	requestID, err := randomID("request")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	client, closeClient, err := newK8sNodeEnrollmentClient(options)
	if err != nil {
		return err
	}
	defer closeClient()
	ctx, cancel := context.WithTimeout(cli.ProcessContext(), options.timeout)
	defer cancel()
	enrollments, err := client.List(
		ctx,
		options.clusterID,
		options.nodeName,
		*includeRevoked,
		&protocolv1.AuditContext{RequestId: requestID},
	)
	if err != nil {
		return k8sNodeControlExitError(err)
	}
	out := make([]k8sNodeEnrollmentOutput, 0, len(enrollments))
	for _, enrollment := range enrollments {
		out = append(out, k8sNodeEnrollmentOutputFromDomain(enrollment, requestID))
	}
	return writeOutput(stdout, options.format, out, func() {
		for _, enrollment := range out {
			_, _ = fmt.Fprintf(
				stdout,
				"%s\t%s\trevision=%d\n",
				enrollment.NodeName,
				enrollment.Status,
				enrollment.Revision,
			)
		}
		_, _ = fmt.Fprintf(stdout, "Request ID: %s\n", requestID)
	})
}

type k8sNodeControlFlagValues struct {
	address        *string
	caCertPath     *string
	tlsServerName  *string
	clientCertPath *string
	clientKeyPath  *string
	clusterID      *string
	nodeName       *string
	timeout        *time.Duration
	format         *string
	requireNode    bool
}

func addK8sNodeControlFlags(flags *flag.FlagSet, requireNode bool) k8sNodeControlFlagValues {
	return k8sNodeControlFlagValues{
		address:        flags.String("addr", envOrDefault("BAO_UNSEALD_ADDR", "127.0.0.1:8443"), "bao-unseald gRPC address."),
		caCertPath:     flags.String("ca-cert", "", "Optional PEM CA certificate for broker TLS."),
		tlsServerName:  flags.String("tls-server-name", "", "Optional TLS server name override."),
		clientCertPath: flags.String("client-cert", "", "PEM client certificate with node-evidence-admin role."),
		clientKeyPath:  flags.String("client-key", "", "PEM client key for broker mTLS."),
		clusterID:      flags.String("cluster-id", "prod-eu1", "Cluster identifier."),
		nodeName:       flags.String("node-name", "", "Optional Kubernetes node name filter."),
		timeout:        flags.Duration("timeout", brokeradmin.DefaultRequestTimeout, "Broker request timeout."),
		format:         flags.String("format", formatText, "Output format: text or json."),
		requireNode:    requireNode,
	}
}

func (values k8sNodeControlFlagValues) options() (k8sNodeControlOptions, error) {
	if err := validateFormat(*values.format); err != nil {
		return k8sNodeControlOptions{}, err
	}
	if strings.TrimSpace(*values.address) == "" || strings.TrimSpace(*values.clusterID) == "" {
		return k8sNodeControlOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-addr and -cluster-id are required"),
		)
	}
	if values.requireNode && strings.TrimSpace(*values.nodeName) == "" {
		return k8sNodeControlOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-node-name is required"))
	}
	if strings.TrimSpace(*values.clientCertPath) == "" || strings.TrimSpace(*values.clientKeyPath) == "" {
		return k8sNodeControlOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-client-cert and -client-key are required"),
		)
	}
	if *values.timeout <= 0 {
		return k8sNodeControlOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	return k8sNodeControlOptions{
		address:        strings.TrimSpace(*values.address),
		caCertPath:     strings.TrimSpace(*values.caCertPath),
		tlsServerName:  strings.TrimSpace(*values.tlsServerName),
		clientCertPath: strings.TrimSpace(*values.clientCertPath),
		clientKeyPath:  strings.TrimSpace(*values.clientKeyPath),
		clusterID:      strings.TrimSpace(*values.clusterID),
		nodeName:       strings.TrimSpace(*values.nodeName),
		timeout:        *values.timeout,
		format:         *values.format,
	}, nil
}

func newK8sNodeEnrollmentClient(
	options k8sNodeControlOptions,
) (brokeradmin.NodeEnrollmentClient, func(), error) {
	dialOptions, err := brokerAdminDialOptions(k8sAdminClientOptions{
		address:        options.address,
		caCertPath:     options.caCertPath,
		tlsServerName:  options.tlsServerName,
		clientCertPath: options.clientCertPath,
		clientKeyPath:  options.clientKeyPath,
		timeout:        options.timeout,
		format:         options.format,
	})
	if err != nil {
		return brokeradmin.NodeEnrollmentClient{}, func() {}, cli.WithExitCode(cli.ExitConfig, err)
	}
	conn, err := grpc.NewClient(options.address, dialOptions...)
	if err != nil {
		return brokeradmin.NodeEnrollmentClient{}, func() {}, cli.WithExitCode(
			cli.ExitConfig,
			fmt.Errorf("create broker client: %w", err),
		)
	}
	return brokeradmin.NodeEnrollmentClient{
		Client: protocolv1.NewEnrollmentServiceClient(conn),
	}, func() { _ = conn.Close() }, nil
}

func parseCertificateHashes(value string) ([]string, error) {
	parts := strings.Split(value, ",")
	hashes := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		canonical, err := nodeevidence.CanonicalSHA256Digest(part)
		if err != nil {
			return nil, cli.WithExitCode(cli.ExitUsage, fmt.Errorf("invalid publisher certificate hash: %w", err))
		}
		hashes = append(hashes, canonical)
	}
	if len(hashes) == 0 {
		return nil, cli.WithExitCode(cli.ExitUsage, errors.New("-publisher-cert-sha256 is required"))
	}
	return hashes, nil
}

func k8sNodeControlExitError(err error) error {
	var denied brokeradmin.DecisionDeniedError
	if errors.As(err, &denied) {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	return cli.WithExitCode(cli.ExitRuntime, err)
}

func k8sNodeEnrollmentOutputFromDomain(
	enrollment nodeevidence.Enrollment,
	requestID string,
) k8sNodeEnrollmentOutput {
	status := "active"
	if !enrollment.Active() {
		status = "revoked"
	}
	return k8sNodeEnrollmentOutput{
		RequestID:                  requestID,
		ClusterID:                  enrollment.ClusterID,
		NodeName:                   enrollment.NodeName,
		NodeUID:                    enrollment.NodeUID,
		ProviderID:                 enrollment.Provider,
		PolicyMode:                 enrollment.TPMPolicy.Mode,
		EnrolledAKPublicHash:       enrollment.TPMPolicy.EnrolledAKPublicHash,
		PublisherCertificateSHA256: enrollment.PublisherCertificateHashes,
		Revision:                   enrollment.Revision,
		EnrolledAt:                 enrollment.EnrolledAt.Format(time.RFC3339),
		UpdatedAt:                  enrollment.UpdatedAt.Format(time.RFC3339),
		RevokedAt:                  formatOptionalTime(enrollment.RevokedAt),
		Status:                     status,
	}
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.Format(time.RFC3339)
}
