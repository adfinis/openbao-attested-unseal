// Package baounsealctl implements the operator lifecycle CLI.
package baounsealctl

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/broker"
	"github.com/adfinis/openbao-attested-unseal/internal/cli"
	"github.com/adfinis/openbao-attested-unseal/internal/enrollment"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"github.com/adfinis/openbao-attested-unseal/internal/recovery"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
	"github.com/adfinis/openbao-attested-unseal/internal/version"
)

const (
	formatText = "text"
	formatJSON = "json"

	approvalModeSingleOperator = "single-operator"
	approvalModeQuorum         = "quorum"
	commandStatus              = "status"
	operationRevoke            = "OPERATION_REVOKE"
	revocationModeBroker       = "broker"
	revocationModeLocalTPM     = "local-tpm"
)

// Execute runs bao-unsealctl.
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
	case "init":
		return initCommand(args[1:], stdout, stderr)
	case commandStatus:
		return statusCommand(args[1:], stdout, stderr)
	case "enroll":
		return enrollCommand(args[1:], stdout, stderr)
	case "recover":
		return recoverCommand(args[1:], stdout, stderr)
	case "rotate":
		return rotateCommand(args[1:], stdout, stderr)
	case "revoke":
		return revokeCommand(args[1:], stdout, stderr)
	case "tpm":
		return tpmCommand(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown command %q", args[0]))
	}
}

func initCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	recoveryPath := flags.String("recovery-package", "", "Path for non-secret recovery metadata.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	keyID := flags.String("key-id", "root", "Wrapping key identifier.")
	policyID := flags.String("policy-id", "development", "Policy identifier.")
	keyringProfile := flags.String("keyring-profile", broker.DevelopmentProfile, "Broker keyring protection profile.")
	shares := flags.Int("shares", recovery.DefaultShares, "Recovery share count.")
	threshold := flags.Int("threshold", recovery.DefaultThreshold, "Recovery threshold.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state is required"))
	}
	if err := validateKeyringProfile(*keyringProfile); err != nil {
		return err
	}
	if strings.TrimSpace(*recoveryPath) == "" {
		*recoveryPath = *statePath + ".recovery.json"
	}

	now := time.Now().UTC()
	material, err := keyring.GenerateKey()
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	packageID, err := randomID("rpkg")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	recoveryPackage, err := recovery.Create(packageID, *clusterID, *keyID, material, *threshold, *shares, now)
	if err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	metadataJSON, err := json.MarshalIndent(recoveryPackage.Metadata, "", "  ")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), *statePath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	if err := store.BootstrapKeyring(cli.ProcessContext(), broker.BootstrapKeyringRequest{
		ClusterID:            *clusterID,
		KeyID:                *keyID,
		Profile:              strings.TrimSpace(*keyringProfile),
		PolicyID:             *policyID,
		Material:             material,
		RecoveryPackageID:    recoveryPackage.Metadata.PackageID,
		RecoveryThreshold:    recoveryPackage.Metadata.Threshold,
		RecoveryShares:       recoveryPackage.Metadata.Shares,
		RecoveryChecksum:     recoveryPackage.Metadata.SecretChecksum,
		RecoveryMetadataJSON: string(metadataJSON),
		CreatedAt:            now,
	}); err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	if err := writeJSONFile(*recoveryPath, recoveryPackage.Metadata); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	auditID, err := audit(cli.ProcessContext(), store, *auditPath, auditInput{
		Subject:   "operator",
		Operation: "OPERATION_INIT",
		ClusterID: *clusterID,
		KeyID:     *keyID,
		Version:   1,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  *policyID,
		Reason:    "cluster initialized",
	})
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	sealConfig := sealConfigSnippet(*clusterID, *keyID)
	out := initOutput{
		AuditID:             auditID,
		RecoveryPackage:     recoveryPackage.Metadata,
		RecoveryPackagePath: *recoveryPath,
		RecoveryShares:      recoveryPackage.Shares,
		KeyringProfile:      strings.TrimSpace(*keyringProfile),
		SealConfig:          sealConfig,
	}
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Initialized cluster %s\n", *clusterID)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", auditID)
		_, _ = fmt.Fprintf(stdout, "Recovery package: %s\n", *recoveryPath)
		_, _ = fmt.Fprintln(stdout, "Recovery shares, print once:")
		for _, share := range recoveryPackage.Shares {
			_, _ = fmt.Fprintf(stdout, "  %s\n", share)
		}
		_, _ = fmt.Fprintln(stdout, sealConfig)
	})
}

func statusCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state is required"))
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), *statePath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	ring, err := store.LoadKeyring(cli.ProcessContext(), *clusterID)
	if err != nil {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	active, err := ring.Active(cli.ProcessContext())
	if err != nil {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	out := statusOutput{
		ClusterID:   *clusterID,
		Ready:       true,
		ActiveKeyID: active.Ref.String(),
	}
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Cluster: %s\n", out.ClusterID)
		_, _ = fmt.Fprintf(stdout, "Ready: %t\n", out.Ready)
		_, _ = fmt.Fprintf(stdout, "Active key: %s\n", out.ActiveKeyID)
	})
}

func enrollCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected enroll subcommand"))
	}
	switch args[0] {
	case "request":
		return enrollRequestCommand(args[1:], stdout, stderr)
	case "issue":
		return enrollIssueCommand(args[1:], stdout, stderr)
	case "apply":
		return enrollApplyCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown enroll subcommand %q", args[0]))
	}
}

func enrollRequestCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("enroll request", flag.ContinueOnError)
	flags.SetOutput(stderr)
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	subjectID := flags.String("subject-id", "", "Subject identifier.")
	outPath := flags.String("out", "", "Enrollment request output path.")
	operationsRaw := flags.String("operations", "wrap,unwrap", "Comma-separated desired operations.")
	ttl := flags.Duration("ttl", 15*time.Minute, "Request TTL.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*subjectID) == "" || strings.TrimSpace(*outPath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-subject-id and -out are required"))
	}
	operations, err := parseOperations(*operationsRaw)
	if err != nil {
		return err
	}
	requestID, err := randomID("req")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	nonce, err := randomID("nonce")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	request, err := enrollment.NewRequest(enrollment.RequestOptions{
		RequestID:         requestID,
		ClusterID:         *clusterID,
		SubjectID:         *subjectID,
		AllowedOperations: operations,
		EvidenceFormat:    "development-subject",
		EvidencePayload:   []byte(*subjectID),
		PublicIdentity:    "development:" + *subjectID,
		Nonce:             nonce,
		ExpiresAt:         time.Now().Add(*ttl),
	})
	if err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := writeJSONFile(*outPath, request); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	auditID, err := randomID("audit")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	out := enrollRequestOutput{
		AuditID:   auditID,
		RequestID: request.RequestID,
		Path:      *outPath,
	}
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Enrollment request: %s\n", *outPath)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", auditID)
	})
}

func enrollIssueCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseEnrollIssueOptions(args, stderr)
	if err != nil {
		return err
	}
	grant, auditID, err := issueEnrollmentGrant(options)
	if err != nil {
		return err
	}
	out := enrollGrantOutput{AuditID: auditID, GrantID: grant.GrantID, Path: options.grantPath}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Enrollment grant: %s\n", options.grantPath)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", auditID)
	})
}

type enrollIssueOptions struct {
	statePath    string
	auditPath    string
	requestPath  string
	grantPath    string
	keyID        string
	policyID     string
	approvalMode string
	ttl          time.Duration
	format       string
}

func parseEnrollIssueOptions(args []string, stderr io.Writer) (enrollIssueOptions, error) {
	flags := flag.NewFlagSet("enroll issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	requestPath := flags.String("request", "", "Enrollment request path.")
	grantPath := flags.String("grant", "", "Enrollment grant output path.")
	keyID := flags.String("key-id", "root", "Wrapping key identifier.")
	policyID := flags.String("policy-id", "development", "Policy identifier.")
	approvalMode := flags.String(
		"approval-mode",
		approvalModeSingleOperator,
		"Enrollment approval mode: single-operator or quorum.",
	)
	ttl := flags.Duration("ttl", 15*time.Minute, "Grant TTL.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return enrollIssueOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return enrollIssueOptions{}, err
	}
	if strings.TrimSpace(*statePath) == "" ||
		strings.TrimSpace(*requestPath) == "" ||
		strings.TrimSpace(*grantPath) == "" {
		return enrollIssueOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-state, -request, and -grant are required"),
		)
	}
	normalizedApprovalMode, err := validateApprovalMode(*approvalMode)
	if err != nil {
		return enrollIssueOptions{}, err
	}
	return enrollIssueOptions{
		statePath:    *statePath,
		auditPath:    *auditPath,
		requestPath:  *requestPath,
		grantPath:    *grantPath,
		keyID:        *keyID,
		policyID:     *policyID,
		approvalMode: normalizedApprovalMode,
		ttl:          *ttl,
		format:       *format,
	}, nil
}

func issueEnrollmentGrant(options enrollIssueOptions) (enrollment.Grant, string, error) {
	var request enrollment.Request
	if err := readJSONFile(options.requestPath, &request); err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitConfig, err)
	}
	now := time.Now().UTC()
	_, privateKey, err := enrollment.GenerateIssuer(nil)
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	grantID, err := randomID("grant")
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	grant, err := enrollment.IssueGrant(request, privateKey, enrollment.GrantOptions{
		GrantID:      grantID,
		KeyID:        options.keyID,
		PolicyID:     options.policyID,
		ApprovalMode: options.approvalMode,
		ExpiresAt:    now.Add(options.ttl),
		OneTime:      true,
	}, now)
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitUsage, err)
	}
	grantBody, err := marshalStrict(grant)
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	requestBody, err := marshalStrict(request)
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	if err := store.InsertSubject(cli.ProcessContext(), request.ClusterID, request.SubjectID, now); err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	requestExpiry, _ := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err := store.InsertEnrollmentRequest(cli.ProcessContext(), broker.EnrollmentRequestRecord{
		RequestID: request.RequestID,
		ClusterID: request.ClusterID,
		Subject:   request.SubjectID,
		Body:      string(requestBody),
		ExpiresAt: requestExpiry,
		CreatedAt: now,
	}); err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	grantExpiry, _ := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err := store.InsertEnrollmentGrant(cli.ProcessContext(), broker.EnrollmentGrantRecord{
		GrantID:   grant.GrantID,
		RequestID: grant.RequestID,
		ClusterID: grant.ClusterID,
		Subject:   grant.SubjectID,
		Body:      string(grantBody),
		ExpiresAt: grantExpiry,
		CreatedAt: now,
	}); err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	if err := writeJSONFile(options.grantPath, grant); err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitConfig, err)
	}
	auditID, err := audit(cli.ProcessContext(), store, options.auditPath, auditInput{
		Subject:   request.SubjectID,
		Operation: protocolv1.Operation_OPERATION_ENROLL.String(),
		ClusterID: request.ClusterID,
		KeyID:     options.keyID,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  options.policyID,
		Reason:    "enrollment grant issued",
	})
	if err != nil {
		return enrollment.Grant{}, "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	return grant, auditID, nil
}

func enrollApplyCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseEnrollApplyOptions(args, stderr)
	if err != nil {
		return err
	}
	out, err := applyEnrollmentGrant(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Enrollment applied for %s\n", out.SubjectID)
		_, _ = fmt.Fprintf(stdout, "Local trust state: %s\n", out.LocalStatePath)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
	})
}

type enrollApplyOptions struct {
	statePath         string
	auditPath         string
	grantPath         string
	expectedClusterID string
	localStatePath    string
	format            string
}

func parseEnrollApplyOptions(args []string, stderr io.Writer) (enrollApplyOptions, error) {
	flags := flag.NewFlagSet("enroll apply", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	grantPath := flags.String("grant", "", "Enrollment grant path.")
	expectedClusterID := flags.String("cluster-id", "", "Expected grant cluster identifier.")
	localStatePath := flags.String("local-state", "", "Local broker trust metadata output path.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return enrollApplyOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return enrollApplyOptions{}, err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*grantPath) == "" {
		return enrollApplyOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-state and -grant are required"))
	}
	if strings.TrimSpace(*localStatePath) == "" {
		*localStatePath = *grantPath + ".local.json"
	}
	return enrollApplyOptions{
		statePath:         *statePath,
		auditPath:         *auditPath,
		grantPath:         *grantPath,
		expectedClusterID: strings.TrimSpace(*expectedClusterID),
		localStatePath:    *localStatePath,
		format:            *format,
	}, nil
}

func applyEnrollmentGrant(options enrollApplyOptions) (enrollApplyOutput, error) {
	var grant enrollment.Grant
	if err := readJSONFile(options.grantPath, &grant); err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	now := time.Now().UTC()
	if err := grant.Verify(now); err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if options.expectedClusterID != "" && grant.ClusterID != options.expectedClusterID {
		return enrollApplyOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf("grant cluster %q does not match expected cluster %q", grant.ClusterID, options.expectedClusterID),
		)
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	if err := checkBrokerReady(cli.ProcessContext(), store, grant.ClusterID); err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if err := store.ConsumeEnrollmentGrant(cli.ProcessContext(), grant.GrantID, now); err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if err := store.InsertSubject(cli.ProcessContext(), grant.ClusterID, grant.SubjectID, now); err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	if err := writeLocalTrustState(options.localStatePath, grant, now); err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	auditID, err := audit(cli.ProcessContext(), store, options.auditPath, auditInput{
		Subject:   grant.SubjectID,
		Operation: protocolv1.Operation_OPERATION_ENROLL.String(),
		ClusterID: grant.ClusterID,
		KeyID:     grant.KeyID,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  grant.PolicyID,
		Reason:    "enrollment grant applied",
	})
	if err != nil {
		return enrollApplyOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	return enrollApplyOutput{
		AuditID:        auditID,
		GrantID:        grant.GrantID,
		SubjectID:      grant.SubjectID,
		LocalStatePath: options.localStatePath,
	}, nil
}

func checkBrokerReady(ctx context.Context, store *broker.SQLiteStore, clusterID string) error {
	ring, err := store.LoadKeyring(ctx, clusterID)
	if err != nil {
		return fmt.Errorf("broker status check failed: %w", err)
	}
	if _, err := ring.Active(ctx); err != nil {
		return fmt.Errorf("broker status check failed: %w", err)
	}
	return nil
}

func writeLocalTrustState(path string, grant enrollment.Grant, now time.Time) error {
	trust := localTrustState{
		SchemaVersion:     1,
		GrantID:           grant.GrantID,
		RequestID:         grant.RequestID,
		ClusterID:         grant.ClusterID,
		KeyID:             grant.KeyID,
		SubjectID:         grant.SubjectID,
		ApprovalMode:      grant.ApprovalMode,
		AllowedOperations: grant.AllowedOperations,
		PolicyID:          grant.PolicyID,
		IssuerPublicKey:   grant.IssuerPublicKey,
		AppliedAt:         now.Format(time.RFC3339Nano),
		StatusCheckedAt:   now.Format(time.RFC3339Nano),
	}
	return writeJSONFile(path, trust)
}

func recoverCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected recover subcommand"))
	}
	switch args[0] {
	case "begin":
		return recoverBeginCommand(args[1:], stdout, stderr)
	case "enroll":
		return recoverEnrollCommand(args[1:], stdout, stderr)
	case "finish":
		return recoverFinishCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown recover subcommand %q", args[0]))
	}
}

func rotateCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected rotate subcommand"))
	}
	switch args[0] {
	case "start":
		return rotateStartCommand(args[1:], stdout, stderr)
	case "activate":
		return rotateActivateCommand(args[1:], stdout, stderr)
	case "openbao-root":
		return rotateOpenBAORootCommand(args[1:], stdout, stderr)
	case "verify-restart":
		return rotateVerifyRestartCommand(args[1:], stdout, stderr)
	case commandStatus:
		return rotateStatusCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown rotate subcommand %q", args[0]))
	}
}

type rotateStartOptions struct {
	statePath string
	auditPath string
	clusterID string
	keyID     string
	policyID  string
	format    string
}

func rotateStartCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("rotate start", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	keyID := flags.String("key-id", "root", "Wrapping key identifier.")
	policyID := flags.String("policy-id", "rotation", "Policy identifier for the new key version.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state is required"))
	}
	options := rotateStartOptions{
		statePath: *statePath,
		auditPath: *auditPath,
		clusterID: strings.TrimSpace(*clusterID),
		keyID:     strings.TrimSpace(*keyID),
		policyID:  strings.TrimSpace(*policyID),
		format:    *format,
	}
	out, err := startRotation(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Rotation operation: %s\n", out.OperationID)
		_, _ = fmt.Fprintf(stdout, "Key: %s/%s v%d -> v%d\n", out.ClusterID, out.KeyID, out.FromVersion, out.ToVersion)
		_, _ = fmt.Fprintf(stdout, "Status: %s\n", out.Status)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
	})
}

func startRotation(options rotateStartOptions) (rotateOutput, error) {
	material, err := keyring.GenerateKey()
	if err != nil {
		return rotateOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	operationID, err := randomID("rot")
	if err != nil {
		return rotateOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return rotateOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	operation, err := store.StartRotation(cli.ProcessContext(), broker.RotationStartRequest{
		OperationID: operationID,
		ClusterID:   options.clusterID,
		KeyID:       options.keyID,
		PolicyID:    options.policyID,
		Material:    material,
		CreatedAt:   time.Now().UTC(),
	})
	if err != nil {
		return rotateOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	auditID, err := auditRotation(store, options.auditPath, operation, options.policyID, "rotation started")
	if err != nil {
		return rotateOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	return rotateOutputFromOperation(operation, auditID), nil
}

func rotateActivateCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("rotate activate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	operationID := flags.String("operation-id", "", "Rotation operation identifier.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*operationID) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state and -operation-id are required"))
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), *statePath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	operation, err := store.ActivateRotation(cli.ProcessContext(), strings.TrimSpace(*operationID), time.Now().UTC())
	if err != nil {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	policyID := "rotation"
	keyVersion, err := store.KeyVersion(cli.ProcessContext(), keyring.KeyRef{
		ClusterID: operation.ClusterID,
		KeyID:     operation.KeyID,
		Version:   operation.ToVersion,
	})
	if err == nil {
		policyID = keyVersion.PolicyID
	}
	auditID, err := auditRotation(store, *auditPath, operation, policyID, "rotation activated")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	out := rotateOutputFromOperation(operation, auditID)
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Rotation operation: %s\n", out.OperationID)
		_, _ = fmt.Fprintf(stdout, "Status: %s\n", out.Status)
		_, _ = fmt.Fprintf(stdout, "Active key version: %d\n", out.ToVersion)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
	})
}

func rotateStatusCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("rotate status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	operationID := flags.String("operation-id", "", "Rotation operation identifier.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*operationID) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state and -operation-id are required"))
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), *statePath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	operation, err := store.RotationOperation(cli.ProcessContext(), strings.TrimSpace(*operationID))
	if err != nil {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	verifications, err := store.RotationVerifications(cli.ProcessContext(), operation.OperationID)
	if err != nil {
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	out := rotateOutputFromOperation(operation, "")
	out.Verifications = rotationVerificationOutputs(verifications)
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Rotation operation: %s\n", out.OperationID)
		_, _ = fmt.Fprintf(stdout, "Key: %s/%s v%d -> v%d\n", out.ClusterID, out.KeyID, out.FromVersion, out.ToVersion)
		_, _ = fmt.Fprintf(stdout, "Status: %s\n", out.Status)
		printRotationVerifications(stdout, out.Verifications)
	})
}

type rotateOpenBAORootOptions struct {
	statePath     string
	auditPath     string
	operationID   string
	address       string
	caCertPath    string
	tlsServerName string
	timeout       time.Duration
	format        string
}

func rotateOpenBAORootCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("rotate openbao-root", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	operationID := flags.String("operation-id", "", "Rotation operation identifier.")
	address := flags.String("addr", envOrDefault("BAO_ADDR", "https://127.0.0.1:8200"), "OpenBao API address.")
	caCertPath := flags.String("ca-cert", "", "Optional PEM CA certificate for OpenBao TLS.")
	tlsServerName := flags.String("tls-server-name", "", "Optional TLS server name override.")
	timeout := flags.Duration("timeout", 30*time.Second, "OpenBao request timeout.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*operationID) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state and -operation-id are required"))
	}
	if *timeout <= 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	options := rotateOpenBAORootOptions{
		statePath:     *statePath,
		auditPath:     *auditPath,
		operationID:   strings.TrimSpace(*operationID),
		address:       strings.TrimSpace(*address),
		caCertPath:    strings.TrimSpace(*caCertPath),
		tlsServerName: strings.TrimSpace(*tlsServerName),
		timeout:       *timeout,
		format:        *format,
	}
	out, err := rotateOpenBAORoot(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Rotation operation: %s\n", out.OperationID)
		_, _ = fmt.Fprintf(stdout, "Key: %s/%s v%d -> v%d\n", out.ClusterID, out.KeyID, out.FromVersion, out.ToVersion)
		_, _ = fmt.Fprintf(stdout, "Status: %s\n", out.Status)
		_, _ = fmt.Fprintf(stdout, "OpenBao endpoint: %s\n", out.Endpoint)
		_, _ = fmt.Fprintf(stdout, "HTTP status: %d\n", out.HTTPStatus)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
	})
}

func rotateOpenBAORoot(options rotateOpenBAORootOptions) (rotateOpenBAORootOutput, error) {
	token := strings.TrimSpace(os.Getenv("BAO_TOKEN"))
	if token == "" {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitConfig, errors.New("BAO_TOKEN is required"))
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	operation, err := store.RotationOperation(cli.ProcessContext(), options.operationID)
	if err != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if operation.Status != broker.RotationStatusActivated {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf(
				"%w: rotation must be activated before OpenBao root rotation; status is %q",
				broker.ErrRotationInvalidTransition,
				operation.Status,
			),
		)
	}
	keyVersion, err := store.KeyVersion(cli.ProcessContext(), keyring.KeyRef{
		ClusterID: operation.ClusterID,
		KeyID:     operation.KeyID,
		Version:   operation.ToVersion,
	})
	policyID := "rotation"
	if err == nil {
		policyID = keyVersion.PolicyID
	}
	endpoint, err := openBaoEndpoint(options.address, "/v1/sys/rotate/root")
	if err != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	if _, err := auditRotationWithDecision(
		store,
		options.auditPath,
		operation,
		policyID,
		"POLICY_DECISION_STATE_ALLOW",
		"openbao root key rotation requested",
	); err != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	statusCode, callErr := callOpenBaoRotateRoot(cli.ProcessContext(), options, endpoint, token)
	decision := "POLICY_DECISION_STATE_ALLOW"
	reason := "openbao root key rotation completed"
	if callErr != nil {
		decision = "POLICY_DECISION_STATE_DENY"
		reason = "openbao root key rotation failed"
	}
	auditID, auditErr := auditRotationWithDecision(store, options.auditPath, operation, policyID, decision, reason)
	if auditErr != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitRuntime, auditErr)
	}
	if callErr != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitRuntime, callErr)
	}
	verification, err := store.RecordRotationVerification(
		cli.ProcessContext(),
		operation.OperationID,
		broker.RotationVerificationOpenBAORoot,
		fmt.Sprintf("OpenBao /sys/rotate/root returned HTTP %d", statusCode),
		time.Now().UTC(),
	)
	if err != nil {
		return rotateOpenBAORootOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	return rotateOpenBAORootOutput{
		AuditID:      auditID,
		OperationID:  operation.OperationID,
		ClusterID:    operation.ClusterID,
		KeyID:        operation.KeyID,
		FromVersion:  operation.FromVersion,
		ToVersion:    operation.ToVersion,
		Status:       string(operation.Status),
		Endpoint:     endpoint,
		HTTPStatus:   statusCode,
		Verification: rotationVerificationOutputFromRecord(verification),
	}, nil
}

func callOpenBaoRotateRoot(
	ctx context.Context,
	options rotateOpenBAORootOptions,
	endpoint string,
	token string,
) (int, error) {
	client, err := newOpenBaoClient(options.caCertPath, options.tlsServerName, options.timeout)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("create OpenBao request: %w", err)
	}
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("User-Agent", "bao-unsealctl")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("call OpenBao root rotation endpoint: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("OpenBao root rotation failed with HTTP status %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

type rotateVerifyRestartOptions struct {
	statePath     string
	auditPath     string
	operationID   string
	address       string
	caCertPath    string
	tlsServerName string
	timeout       time.Duration
	format        string
}

func rotateVerifyRestartCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("rotate verify-restart", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	operationID := flags.String("operation-id", "", "Rotation operation identifier.")
	address := flags.String("addr", envOrDefault("BAO_ADDR", "https://127.0.0.1:8200"), "OpenBao API address.")
	caCertPath := flags.String("ca-cert", "", "Optional PEM CA certificate for OpenBao TLS.")
	tlsServerName := flags.String("tls-server-name", "", "Optional TLS server name override.")
	timeout := flags.Duration("timeout", 30*time.Second, "OpenBao request timeout.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*operationID) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state and -operation-id are required"))
	}
	if *timeout <= 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-timeout must be greater than zero"))
	}
	options := rotateVerifyRestartOptions{
		statePath:     *statePath,
		auditPath:     *auditPath,
		operationID:   strings.TrimSpace(*operationID),
		address:       strings.TrimSpace(*address),
		caCertPath:    strings.TrimSpace(*caCertPath),
		tlsServerName: strings.TrimSpace(*tlsServerName),
		timeout:       *timeout,
		format:        *format,
	}
	out, err := rotateVerifyRestart(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Rotation operation: %s\n", out.OperationID)
		_, _ = fmt.Fprintf(stdout, "Verification: %s\n", out.Verification.Name)
		_, _ = fmt.Fprintf(stdout, "OpenBao initialized: %t\n", out.OpenBaoInitialized)
		_, _ = fmt.Fprintf(stdout, "OpenBao sealed: %t\n", out.OpenBaoSealed)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
	})
}

func rotateVerifyRestart(options rotateVerifyRestartOptions) (rotateVerifyRestartOutput, error) {
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	operation, err := store.RotationOperation(cli.ProcessContext(), options.operationID)
	if err != nil {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if operation.Status != broker.RotationStatusActivated {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf(
				"%w: rotation must be activated before restart verification; status is %q",
				broker.ErrRotationInvalidTransition,
				operation.Status,
			),
		)
	}
	verifications, err := store.RotationVerifications(cli.ProcessContext(), operation.OperationID)
	if err != nil {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if !hasRotationVerification(verifications, broker.RotationVerificationOpenBAORoot) {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf("%w: openbao-root verification is required first", broker.ErrRotationInvalidTransition),
		)
	}
	endpoint, err := openBaoEndpoint(options.address, "/v1/sys/seal-status")
	if err != nil {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	status, err := callOpenBaoSealStatus(cli.ProcessContext(), options, endpoint)
	if err != nil {
		_, _ = auditRotationWithDecision(
			store,
			options.auditPath,
			operation,
			"rotation",
			"POLICY_DECISION_STATE_DENY",
			"openbao restart verification failed",
		)
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if !status.Initialized || status.Sealed {
		_, _ = auditRotationWithDecision(
			store,
			options.auditPath,
			operation,
			"rotation",
			"POLICY_DECISION_STATE_DENY",
			"openbao restart verification failed",
		)
		return rotateVerifyRestartOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf(
				"OpenBao seal status initialized=%t sealed=%t, want initialized=true sealed=false",
				status.Initialized,
				status.Sealed,
			),
		)
	}
	detail := fmt.Sprintf(
		"OpenBao seal-status initialized=%t sealed=%t type=%s",
		status.Initialized,
		status.Sealed,
		status.Type,
	)
	verification, err := store.RecordRotationVerification(
		cli.ProcessContext(),
		operation.OperationID,
		broker.RotationVerificationRestart,
		detail,
		time.Now().UTC(),
	)
	if err != nil {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	auditID, err := auditRotationWithDecision(
		store,
		options.auditPath,
		operation,
		"rotation",
		"POLICY_DECISION_STATE_ALLOW",
		"openbao restart verification completed",
	)
	if err != nil {
		return rotateVerifyRestartOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	return rotateVerifyRestartOutput{
		AuditID:            auditID,
		OperationID:        operation.OperationID,
		ClusterID:          operation.ClusterID,
		KeyID:              operation.KeyID,
		FromVersion:        operation.FromVersion,
		ToVersion:          operation.ToVersion,
		Status:             string(operation.Status),
		Endpoint:           endpoint,
		OpenBaoInitialized: status.Initialized,
		OpenBaoSealed:      status.Sealed,
		OpenBaoSealType:    status.Type,
		Verification:       rotationVerificationOutputFromRecord(verification),
	}, nil
}

type openBaoSealStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
}

func callOpenBaoSealStatus(
	ctx context.Context,
	options rotateVerifyRestartOptions,
	endpoint string,
) (openBaoSealStatus, error) {
	client, err := newOpenBaoClient(options.caCertPath, options.tlsServerName, options.timeout)
	if err != nil {
		return openBaoSealStatus{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return openBaoSealStatus{}, fmt.Errorf("create OpenBao seal-status request: %w", err)
	}
	req.Header.Set("X-Vault-Request", "true")
	req.Header.Set("User-Agent", "bao-unsealctl")
	resp, err := client.Do(req)
	if err != nil {
		return openBaoSealStatus{}, fmt.Errorf("call OpenBao seal-status endpoint: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return openBaoSealStatus{}, fmt.Errorf("OpenBao seal-status failed with HTTP status %d", resp.StatusCode)
	}
	var status openBaoSealStatus
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	if err := decoder.Decode(&status); err != nil {
		return openBaoSealStatus{}, fmt.Errorf("decode OpenBao seal-status: %w", err)
	}
	return status, nil
}

func newOpenBaoClient(caCertPath string, tlsServerName string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caCertPath != "" || tlsServerName != "" {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: tlsServerName,
		}
		if caCertPath != "" {
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			// #nosec G304 -- CA certificate path is operator supplied.
			caPEM, err := os.ReadFile(caCertPath)
			if err != nil {
				return nil, fmt.Errorf("read CA certificate: %w", err)
			}
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, errors.New("CA certificate did not contain a PEM certificate")
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func openBaoEndpoint(address string, path string) (string, error) {
	if strings.TrimSpace(address) == "" {
		return "", errors.New("OpenBao address is required")
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("parse OpenBao address: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("OpenBao address must use http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("OpenBao address must include a host")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}

func envOrDefault(name string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func auditRotation(
	store *broker.SQLiteStore,
	auditPath string,
	operation broker.RotationOperation,
	policyID string,
	reason string,
) (string, error) {
	return audit(cli.ProcessContext(), store, auditPath, auditInput{
		Subject:   "operator",
		Operation: protocolv1.Operation_OPERATION_ROTATE.String(),
		ClusterID: operation.ClusterID,
		KeyID:     operation.KeyID,
		Version:   operation.ToVersion,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  policyID,
		Reason:    reason,
	})
}

func auditRotationWithDecision(
	store *broker.SQLiteStore,
	auditPath string,
	operation broker.RotationOperation,
	policyID string,
	decision string,
	reason string,
) (string, error) {
	return audit(cli.ProcessContext(), store, auditPath, auditInput{
		Subject:   "operator",
		Operation: protocolv1.Operation_OPERATION_ROTATE.String(),
		ClusterID: operation.ClusterID,
		KeyID:     operation.KeyID,
		Version:   operation.ToVersion,
		Decision:  decision,
		PolicyID:  policyID,
		Reason:    reason,
	})
}

func rotateOutputFromOperation(operation broker.RotationOperation, auditID string) rotateOutput {
	return rotateOutput{
		AuditID:     auditID,
		OperationID: operation.OperationID,
		ClusterID:   operation.ClusterID,
		KeyID:       operation.KeyID,
		FromVersion: operation.FromVersion,
		ToVersion:   operation.ToVersion,
		Status:      string(operation.Status),
	}
}

func rotationVerificationOutputs(records []broker.RotationVerification) []rotationVerificationOutput {
	byName := make(map[broker.RotationVerificationName]broker.RotationVerification, len(records))
	for _, record := range records {
		byName[record.Name] = record
	}
	order := []broker.RotationVerificationName{
		broker.RotationVerificationOpenBAORoot,
		broker.RotationVerificationRestart,
		broker.RotationVerificationKeyVersion,
	}
	out := make([]rotationVerificationOutput, 0, len(order))
	for _, name := range order {
		record, ok := byName[name]
		if !ok {
			out = append(out, rotationVerificationOutput{Name: string(name), Verified: false})
			continue
		}
		out = append(out, rotationVerificationOutputFromRecord(record))
	}
	return out
}

func rotationVerificationOutputFromRecord(record broker.RotationVerification) rotationVerificationOutput {
	return rotationVerificationOutput{
		Name:       string(record.Name),
		Verified:   true,
		VerifiedAt: record.VerifiedAt.UTC().Format(time.RFC3339Nano),
		Detail:     record.Detail,
	}
}

func hasRotationVerification(
	records []broker.RotationVerification,
	name broker.RotationVerificationName,
) bool {
	for _, record := range records {
		if record.Name == name {
			return true
		}
	}
	return false
}

func printRotationVerifications(stdout io.Writer, verifications []rotationVerificationOutput) {
	if len(verifications) == 0 {
		return
	}
	_, _ = fmt.Fprintln(stdout, "Verifications:")
	for _, verification := range verifications {
		if verification.Verified {
			_, _ = fmt.Fprintf(stdout, "  %s: verified", verification.Name)
			if verification.VerifiedAt != "" {
				_, _ = fmt.Fprintf(stdout, " at %s", verification.VerifiedAt)
			}
			if verification.Detail != "" {
				_, _ = fmt.Fprintf(stdout, " (%s)", verification.Detail)
			}
			_, _ = fmt.Fprintln(stdout)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "  %s: pending\n", verification.Name)
	}
}

func revokeCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected revoke subcommand"))
	}
	switch args[0] {
	case "subject":
		return revokeSubjectCommand(args[1:], stdout, stderr)
	case commandStatus:
		return revokeStatusCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown revoke subcommand %q", args[0]))
	}
}

type revokeSubjectOptions struct {
	statePath    string
	auditPath    string
	clusterID    string
	subjectID    string
	mode         string
	rotationPlan string
	format       string
}

func revokeSubjectCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("revoke subject", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	subjectID := flags.String("subject-id", "", "Subject identifier.")
	mode := flags.String("mode", revocationModeBroker, "Revocation mode: broker or local-tpm.")
	rotationPlan := flags.String("rotation-plan", "", "Required rotation plan identifier for local-tpm mode.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	normalizedMode, err := validateRevocationMode(*mode)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*subjectID) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state and -subject-id are required"))
	}
	if normalizedMode == revocationModeLocalTPM && strings.TrimSpace(*rotationPlan) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-rotation-plan is required for local-tpm revocation"))
	}
	options := revokeSubjectOptions{
		statePath:    *statePath,
		auditPath:    *auditPath,
		clusterID:    strings.TrimSpace(*clusterID),
		subjectID:    strings.TrimSpace(*subjectID),
		mode:         normalizedMode,
		rotationPlan: strings.TrimSpace(*rotationPlan),
		format:       *format,
	}
	out, err := revokeSubject(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Revoked subject: %s\n", out.SubjectID)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
		for _, warning := range out.Warnings {
			_, _ = fmt.Fprintf(stdout, "Warning: %s\n", warning)
		}
	})
}

func revokeSubject(options revokeSubjectOptions) (revokeSubjectOutput, error) {
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return revokeSubjectOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	if err := store.RevokeSubject(cli.ProcessContext(), options.clusterID, options.subjectID); err != nil {
		return revokeSubjectOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	auditID, err := audit(cli.ProcessContext(), store, options.auditPath, auditInput{
		Subject:   options.subjectID,
		Operation: operationRevoke,
		ClusterID: options.clusterID,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  "revocation",
		Reason:    "subject revoked",
	})
	if err != nil {
		return revokeSubjectOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	return revokeSubjectOutput{
		AuditID:      auditID,
		ClusterID:    options.clusterID,
		SubjectID:    options.subjectID,
		Revoked:      true,
		Mode:         options.mode,
		RotationPlan: options.rotationPlan,
		Warnings:     revocationWarnings(options.mode),
	}, nil
}

func revokeStatusCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("revoke status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Path to broker SQLite state.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	subjectID := flags.String("subject-id", "", "Subject identifier.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*subjectID) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-state and -subject-id are required"))
	}
	cluster := strings.TrimSpace(*clusterID)
	subject := strings.TrimSpace(*subjectID)
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), *statePath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	revoked := false
	if _, err := store.Subject(cli.ProcessContext(), cluster, subject); err != nil {
		if !errors.Is(err, broker.ErrSubjectRevoked) {
			return cli.WithExitCode(cli.ExitCheckFailed, err)
		}
		revoked = true
	}
	out := revokeStatusOutput{ClusterID: cluster, SubjectID: subject, Revoked: revoked}
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Subject: %s\n", out.SubjectID)
		_, _ = fmt.Fprintf(stdout, "Revoked: %t\n", out.Revoked)
	})
}

func tpmCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return cli.WithExitCode(cli.ExitUsage, errors.New("expected tpm subcommand"))
	}
	switch args[0] {
	case "provision":
		return tpmProvisionCommand(args[1:], stdout, stderr)
	case commandStatus:
		return tpmStatusCommand(args[1:], stdout, stderr)
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unknown tpm subcommand %q", args[0]))
	}
}

type tpmProvisionOptions struct {
	statePath         string
	packagePath       string
	sharesPath        string
	expectedClusterID string
	keyVersion        uint32
	policyMode        string
	pcrBank           string
	pcrs              []int
	policyID          string
	tpmDevice         string
	format            string
}

func tpmProvisionCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseTPMProvisionOptions(args, stderr)
	if err != nil {
		return err
	}
	out, err := provisionLocalTPM(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Local TPM state: %s\n", out.StatePath)
		_, _ = fmt.Fprintf(stdout, "Key: %s\n", out.KeyID)
		_, _ = fmt.Fprintf(stdout, "Policy: %s\n", out.PolicyMode)
		for _, warning := range out.Warnings {
			_, _ = fmt.Fprintf(stdout, "Warning: %s\n", warning)
		}
		_, _ = fmt.Fprintln(stdout, out.SealConfig)
	})
}

func parseTPMProvisionOptions(args []string, stderr io.Writer) (tpmProvisionOptions, error) {
	flags := flag.NewFlagSet("tpm provision", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state-path", "", "Local TPM state directory.")
	packagePath := flags.String("package", "", "Recovery package metadata path.")
	sharesPath := flags.String("shares-file", "", "Recovery shares file.")
	expectedClusterID := flags.String("cluster-id", "", "Expected recovery package cluster identifier.")
	keyVersion := flags.Uint("key-version", 1, "Wrapping key version to provision.")
	policyMode := flags.String("policy", tpmlocal.PolicyModeTPMOnly, "TPM policy: tpm-only or secureboot.")
	pcrBank := flags.String("pcr-bank", tpmlocal.HashSHA256, "PCR bank for secureboot policy.")
	pcrsRaw := flags.String("pcrs", "7", "Comma-separated PCR indexes for secureboot policy.")
	policyID := flags.String("policy-id", "local-tpm", "Local key policy identifier.")
	tpmDevice := flags.String("tpm-device", "", "TPM device path or swtpm Unix socket.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return tpmProvisionOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return tpmProvisionOptions{}, err
	}
	if strings.TrimSpace(*statePath) == "" ||
		strings.TrimSpace(*packagePath) == "" ||
		strings.TrimSpace(*sharesPath) == "" {
		return tpmProvisionOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-state-path, -package, and -shares-file are required"),
		)
	}
	mode, err := validateTPMPolicyMode(*policyMode)
	if err != nil {
		return tpmProvisionOptions{}, err
	}
	pcrs, err := parsePCRIndexes(*pcrsRaw)
	if err != nil {
		return tpmProvisionOptions{}, err
	}
	parsedKeyVersion, err := parseKeyVersion(*keyVersion)
	if err != nil {
		return tpmProvisionOptions{}, err
	}
	if err := keyring.ValidateIdentifier(*policyID); err != nil {
		return tpmProvisionOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	return tpmProvisionOptions{
		statePath:         *statePath,
		packagePath:       *packagePath,
		sharesPath:        *sharesPath,
		expectedClusterID: strings.TrimSpace(*expectedClusterID),
		keyVersion:        parsedKeyVersion,
		policyMode:        mode,
		pcrBank:           strings.ToLower(strings.TrimSpace(*pcrBank)),
		pcrs:              pcrs,
		policyID:          strings.TrimSpace(*policyID),
		tpmDevice:         strings.TrimSpace(*tpmDevice),
		format:            *format,
	}, nil
}

func provisionLocalTPM(options tpmProvisionOptions) (tpmProvisionOutput, error) {
	var metadata recovery.PackageMetadata
	if err := readJSONFile(options.packagePath, &metadata); err != nil {
		return tpmProvisionOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	if options.expectedClusterID != "" && metadata.ClusterID != options.expectedClusterID {
		return tpmProvisionOutput{}, cli.WithExitCode(
			cli.ExitCheckFailed,
			fmt.Errorf(
				"recovery package cluster %q does not match expected cluster %q",
				metadata.ClusterID,
				options.expectedClusterID,
			),
		)
	}
	shares, err := readSharesFile(options.sharesPath)
	if err != nil {
		return tpmProvisionOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	secret, err := recovery.Recover(metadata, shares)
	if err != nil {
		return tpmProvisionOutput{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	selection := tpmlocal.PCRSelection{}
	if options.policyMode == tpmlocal.PolicyModeSecureBoot {
		selection = tpmlocal.PCRSelection{Hash: options.pcrBank, PCRs: options.pcrs}
	}
	ref := keyring.KeyRef{
		ClusterID: metadata.ClusterID,
		KeyID:     metadata.KeyID,
		Version:   options.keyVersion,
	}
	localMetadata, err := tpmlocal.StoreLocalKey(
		cli.ProcessContext(),
		options.statePath,
		tpmlocal.Device{Path: options.tpmDevice},
		keyring.KeyVersion{
			Ref:       ref,
			Status:    keyring.StatusActive,
			Algorithm: keyring.AlgorithmAES256GCM,
			PolicyID:  options.policyID,
			Material:  secret,
		},
		options.policyMode,
		selection,
	)
	if err != nil {
		return tpmProvisionOutput{}, cli.WithExitCode(cli.ExitRuntime, err)
	}
	sealConfig := localTPMSealConfigSnippet(ref, options.statePath, options.tpmDevice)
	return tpmProvisionOutput{
		StatePath:  options.statePath,
		KeyID:      ref.String(),
		PolicyMode: localMetadata.TPMPolicy.Mode,
		Warnings:   []string{tpmlocal.RevocationWarning},
		SealConfig: sealConfig,
	}, nil
}

type tpmStatusOptions struct {
	statePath  string
	clusterID  string
	keyID      string
	keyVersion uint32
	format     string
}

func tpmStatusCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseTPMStatusOptions(args, stderr)
	if err != nil {
		return err
	}
	ref := keyring.KeyRef{
		ClusterID: options.clusterID,
		KeyID:     options.keyID,
		Version:   options.keyVersion,
	}
	status := tpmlocal.StatusLocal(options.statePath, ref)
	out := tpmStatusOutput{
		StatePath:  options.statePath,
		Ready:      status.Ready,
		KeyID:      ref.String(),
		PolicyMode: status.Mode,
		Warnings:   status.Warnings,
		Errors:     status.Errors,
	}
	if !status.Ready {
		return writeOutput(stdout, options.format, out, func() {
			_, _ = fmt.Fprintf(stdout, "Local TPM state: %s\n", out.StatePath)
			_, _ = fmt.Fprintf(stdout, "Ready: %t\n", out.Ready)
			for _, warning := range out.Warnings {
				_, _ = fmt.Fprintf(stdout, "Warning: %s\n", warning)
			}
			for _, statusErr := range out.Errors {
				_, _ = fmt.Fprintf(stdout, "Error: %s\n", statusErr)
			}
		})
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Local TPM state: %s\n", out.StatePath)
		_, _ = fmt.Fprintf(stdout, "Ready: %t\n", out.Ready)
		_, _ = fmt.Fprintf(stdout, "Key: %s\n", out.KeyID)
		_, _ = fmt.Fprintf(stdout, "Policy: %s\n", out.PolicyMode)
		for _, warning := range out.Warnings {
			_, _ = fmt.Fprintf(stdout, "Warning: %s\n", warning)
		}
	})
}

func parseTPMStatusOptions(args []string, stderr io.Writer) (tpmStatusOptions, error) {
	flags := flag.NewFlagSet("tpm status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state-path", "", "Local TPM state directory.")
	clusterID := flags.String("cluster-id", "prod-eu1", "Cluster identifier.")
	keyID := flags.String("key-id", "root", "Wrapping key identifier.")
	keyVersion := flags.Uint("key-version", 1, "Wrapping key version.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return tpmStatusOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return tpmStatusOptions{}, err
	}
	if strings.TrimSpace(*statePath) == "" {
		return tpmStatusOptions{}, cli.WithExitCode(cli.ExitUsage, errors.New("-state-path is required"))
	}
	parsedKeyVersion, err := parseKeyVersion(*keyVersion)
	if err != nil {
		return tpmStatusOptions{}, err
	}
	return tpmStatusOptions{
		statePath:  *statePath,
		clusterID:  strings.TrimSpace(*clusterID),
		keyID:      strings.TrimSpace(*keyID),
		keyVersion: parsedKeyVersion,
		format:     *format,
	}, nil
}

func recoverBeginCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("recover begin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Optional broker SQLite state for audit.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	packagePath := flags.String("package", "", "Recovery package metadata path.")
	sharesPath := flags.String("shares-file", "", "Recovery shares file.")
	sessionPath := flags.String("session", "", "Recovery session output path.")
	ttl := flags.Duration("ttl", 15*time.Minute, "Recovery session TTL.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*packagePath) == "" || strings.TrimSpace(*sharesPath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-package and -shares-file are required"))
	}
	if strings.TrimSpace(*sessionPath) == "" {
		*sessionPath = *packagePath + ".session"
	}
	var metadata recovery.PackageMetadata
	if err := readJSONFile(*packagePath, &metadata); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	shares, err := readSharesFile(*sharesPath)
	if err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	if _, err := recovery.Recover(metadata, shares); err != nil {
		if _, auditErr := auditWithStatePath(cli.ProcessContext(), *statePath, *auditPath, auditInput{
			Subject:   "operator",
			Operation: protocolv1.Operation_OPERATION_RECOVER.String(),
			ClusterID: metadata.ClusterID,
			KeyID:     metadata.KeyID,
			Decision:  "POLICY_DECISION_STATE_DENY",
			PolicyID:  "recovery",
			Reason:    "recovery shares rejected",
		}); auditErr != nil {
			return cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("write recovery denial audit: %w", auditErr))
		}
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	sessionID, err := randomID("rsess")
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	auditID, err := auditWithStatePath(cli.ProcessContext(), *statePath, *auditPath, auditInput{
		Subject:   "operator",
		Operation: protocolv1.Operation_OPERATION_RECOVER.String(),
		ClusterID: metadata.ClusterID,
		KeyID:     metadata.KeyID,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  "recovery",
		Reason:    "recovery session opened",
	})
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	session := recoverySession{
		SchemaVersion:     1,
		SessionID:         sessionID,
		RecoveryPackageID: metadata.PackageID,
		ClusterID:         metadata.ClusterID,
		KeyID:             metadata.KeyID,
		SecretChecksum:    metadata.SecretChecksum,
		ExpiresAt:         time.Now().Add(*ttl).UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONFile(*sessionPath, session); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	out := recoverBeginOutput{AuditID: auditID, SessionID: sessionID, SessionPath: *sessionPath}
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Recovery session: %s\n", *sessionPath)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", auditID)
	})
}

func recoverEnrollCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	options, err := parseRecoverEnrollOptions(args, stderr)
	if err != nil {
		return err
	}
	out, err := recoverEnroll(options)
	if err != nil {
		return err
	}
	return writeOutput(stdout, options.format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Recovered broker keyring for %s/%s\n", out.ClusterID, out.KeyID)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", out.AuditID)
	})
}

type recoverEnrollOptions struct {
	statePath      string
	auditPath      string
	packagePath    string
	sharesPath     string
	sessionPath    string
	requestPath    string
	policyID       string
	keyringProfile string
	format         string
}

func parseRecoverEnrollOptions(args []string, stderr io.Writer) (recoverEnrollOptions, error) {
	flags := flag.NewFlagSet("recover enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Target broker SQLite state.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	packagePath := flags.String("package", "", "Recovery package metadata path.")
	sharesPath := flags.String("shares-file", "", "Recovery shares file.")
	sessionPath := flags.String("session", "", "Recovery session path.")
	requestPath := flags.String("request", "", "Target enrollment request path.")
	policyID := flags.String("policy-id", "development", "Policy identifier.")
	keyringProfile := flags.String("keyring-profile", broker.DevelopmentProfile, "Broker keyring protection profile.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return recoverEnrollOptions{}, cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return recoverEnrollOptions{}, err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*packagePath) == "" ||
		strings.TrimSpace(*sharesPath) == "" || strings.TrimSpace(*sessionPath) == "" ||
		strings.TrimSpace(*requestPath) == "" {
		return recoverEnrollOptions{}, cli.WithExitCode(
			cli.ExitUsage,
			errors.New("-state, -package, -shares-file, -session, and -request are required"),
		)
	}
	if err := validateKeyringProfile(*keyringProfile); err != nil {
		return recoverEnrollOptions{}, err
	}
	return recoverEnrollOptions{
		statePath:      *statePath,
		auditPath:      *auditPath,
		packagePath:    *packagePath,
		sharesPath:     *sharesPath,
		sessionPath:    *sessionPath,
		requestPath:    *requestPath,
		policyID:       *policyID,
		keyringProfile: strings.TrimSpace(*keyringProfile),
		format:         *format,
	}, nil
}

func recoverEnroll(options recoverEnrollOptions) (recoverEnrollOutput, error) {
	var metadata recovery.PackageMetadata
	if err := readJSONFile(options.packagePath, &metadata); err != nil {
		return recoverEnrollOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	var session recoverySession
	if err := readJSONFile(options.sessionPath, &session); err != nil {
		return recoverEnrollOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	store, err := broker.OpenSQLiteStore(cli.ProcessContext(), options.statePath)
	if err != nil {
		return recoverEnrollOutput{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	defer func() { _ = store.Close() }()
	if err := validateRecoverySessionForEnroll(store, options, metadata, session); err != nil {
		return recoverEnrollOutput{}, err
	}
	targetRequest, err := readRecoveryTargetRequest(store, options, metadata)
	if err != nil {
		return recoverEnrollOutput{}, err
	}
	secret, err := recoverSecretForEnroll(store, options, metadata, targetRequest.SubjectID)
	if err != nil {
		return recoverEnrollOutput{}, err
	}
	now := time.Now().UTC()
	if err := bootstrapRecoveredKeyring(store, options, metadata, secret, targetRequest, now); err != nil {
		return recoverEnrollOutput{}, err
	}
	auditID, err := auditRecoveredKeyring(store, options, metadata, targetRequest)
	if err != nil {
		return recoverEnrollOutput{}, err
	}
	return recoverEnrollOutput{
		AuditID:   auditID,
		ClusterID: metadata.ClusterID,
		KeyID:     metadata.KeyID,
		SubjectID: targetRequest.SubjectID,
	}, nil
}

func validateRecoverySessionForEnroll(
	store *broker.SQLiteStore,
	options recoverEnrollOptions,
	metadata recovery.PackageMetadata,
	session recoverySession,
) error {
	if err := session.Validate(metadata, time.Now()); err != nil {
		if auditErr := auditRecoveryDeny(store, options, metadata, "operator", "recovery session rejected"); auditErr != nil {
			return cli.WithExitCode(cli.ExitRuntime, auditErr)
		}
		return cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	return nil
}

func readRecoveryTargetRequest(
	store *broker.SQLiteStore,
	options recoverEnrollOptions,
	metadata recovery.PackageMetadata,
) (enrollment.Request, error) {
	var targetRequest enrollment.Request
	if err := readJSONFile(options.requestPath, &targetRequest); err != nil {
		return enrollment.Request{}, cli.WithExitCode(cli.ExitConfig, err)
	}
	if err := targetRequest.Validate(time.Now()); err != nil {
		if auditErr := auditRecoveryDeny(
			store,
			options,
			metadata,
			targetRequest.SubjectID,
			"recovery target request rejected",
		); auditErr != nil {
			return enrollment.Request{}, cli.WithExitCode(cli.ExitRuntime, auditErr)
		}
		return enrollment.Request{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	if targetRequest.ClusterID != metadata.ClusterID {
		err := fmt.Errorf(
			"target request cluster %q does not match recovery package cluster %q",
			targetRequest.ClusterID,
			metadata.ClusterID,
		)
		if auditErr := auditRecoveryDeny(
			store,
			options,
			metadata,
			targetRequest.SubjectID,
			"recovery target cluster mismatch",
		); auditErr != nil {
			return enrollment.Request{}, cli.WithExitCode(cli.ExitRuntime, auditErr)
		}
		return enrollment.Request{}, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	return targetRequest, nil
}

func recoverSecretForEnroll(
	store *broker.SQLiteStore,
	options recoverEnrollOptions,
	metadata recovery.PackageMetadata,
	subjectID string,
) ([]byte, error) {
	shares, err := readSharesFile(options.sharesPath)
	if err != nil {
		return nil, cli.WithExitCode(cli.ExitConfig, err)
	}
	secret, err := recovery.Recover(metadata, shares)
	if err != nil {
		if auditErr := auditRecoveryDeny(store, options, metadata, subjectID, "recovery shares rejected"); auditErr != nil {
			return nil, cli.WithExitCode(cli.ExitRuntime, auditErr)
		}
		return nil, cli.WithExitCode(cli.ExitCheckFailed, err)
	}
	return secret, nil
}

func bootstrapRecoveredKeyring(
	store *broker.SQLiteStore,
	options recoverEnrollOptions,
	metadata recovery.PackageMetadata,
	secret []byte,
	targetRequest enrollment.Request,
	now time.Time,
) error {
	metadataJSON, err := marshalStrict(metadata)
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	if err := store.BootstrapKeyring(cli.ProcessContext(), broker.BootstrapKeyringRequest{
		ClusterID:            metadata.ClusterID,
		KeyID:                metadata.KeyID,
		Profile:              options.keyringProfile,
		PolicyID:             options.policyID,
		Material:             secret,
		RecoveryPackageID:    metadata.PackageID,
		RecoveryThreshold:    metadata.Threshold,
		RecoveryShares:       metadata.Shares,
		RecoveryChecksum:     metadata.SecretChecksum,
		RecoveryMetadataJSON: string(metadataJSON),
		CreatedAt:            now,
	}); err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	if err := store.InsertSubject(
		cli.ProcessContext(),
		targetRequest.ClusterID,
		targetRequest.SubjectID,
		now,
	); err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	return nil
}

func auditRecoveredKeyring(
	store *broker.SQLiteStore,
	options recoverEnrollOptions,
	metadata recovery.PackageMetadata,
	targetRequest enrollment.Request,
) (string, error) {
	auditID, err := audit(cli.ProcessContext(), store, options.auditPath, auditInput{
		Subject:   targetRequest.SubjectID,
		Operation: protocolv1.Operation_OPERATION_RECOVER.String(),
		ClusterID: metadata.ClusterID,
		KeyID:     metadata.KeyID,
		Version:   1,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  options.policyID,
		Reason:    "recovery enrollment restored broker keyring",
	})
	if err != nil {
		return "", cli.WithExitCode(cli.ExitRuntime, err)
	}
	return auditID, nil
}

func auditRecoveryDeny(
	store *broker.SQLiteStore,
	options recoverEnrollOptions,
	metadata recovery.PackageMetadata,
	subjectID string,
	reason string,
) error {
	if strings.TrimSpace(subjectID) == "" {
		subjectID = "operator"
	}
	_, err := audit(cli.ProcessContext(), store, options.auditPath, auditInput{
		Subject:   subjectID,
		Operation: protocolv1.Operation_OPERATION_RECOVER.String(),
		ClusterID: metadata.ClusterID,
		KeyID:     metadata.KeyID,
		Decision:  "POLICY_DECISION_STATE_DENY",
		PolicyID:  options.policyID,
		Reason:    reason,
	})
	if err != nil {
		return fmt.Errorf("write recovery denial audit: %w", err)
	}
	return nil
}

func recoverFinishCommand(args []string, stdout io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("recover finish", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "Optional broker SQLite state for audit.")
	auditPath := flags.String("audit-file", "", "Optional JSONL audit file path.")
	sessionPath := flags.String("session", "", "Recovery session path.")
	format := flags.String("format", formatText, "Output format: text or json.")
	if err := flags.Parse(args); err != nil {
		return cli.WithExitCode(cli.ExitUsage, err)
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*sessionPath) == "" {
		return cli.WithExitCode(cli.ExitUsage, errors.New("-session is required"))
	}
	var session recoverySession
	if err := readJSONFile(*sessionPath, &session); err != nil {
		return cli.WithExitCode(cli.ExitConfig, err)
	}
	if err := os.Remove(*sessionPath); err != nil {
		return cli.WithExitCode(cli.ExitRuntime, fmt.Errorf("remove recovery session: %w", err))
	}
	auditID, err := auditWithStatePath(cli.ProcessContext(), *statePath, *auditPath, auditInput{
		Subject:   "operator",
		Operation: protocolv1.Operation_OPERATION_RECOVER.String(),
		ClusterID: session.ClusterID,
		KeyID:     session.KeyID,
		Decision:  "POLICY_DECISION_STATE_ALLOW",
		PolicyID:  "recovery",
		Reason:    "recovery session closed",
	})
	if err != nil {
		return cli.WithExitCode(cli.ExitRuntime, err)
	}
	out := recoverFinishOutput{AuditID: auditID, SessionID: session.SessionID}
	return writeOutput(stdout, *format, out, func() {
		_, _ = fmt.Fprintf(stdout, "Recovery session closed: %s\n", session.SessionID)
		_, _ = fmt.Fprintf(stdout, "Audit ID: %s\n", auditID)
	})
}

type auditInput struct {
	Subject   string
	Operation string
	ClusterID string
	KeyID     string
	Version   uint32
	Decision  string
	PolicyID  string
	Reason    string
}

func audit(ctx context.Context, store *broker.SQLiteStore, auditPath string, input auditInput) (string, error) {
	auditID, err := randomID("audit")
	if err != nil {
		return "", err
	}
	event := broker.AuditEvent{
		SchemaVersion: 1,
		AuditID:       auditID,
		Time:          time.Now().UTC().Format(time.RFC3339Nano),
		Subject:       input.Subject,
		Operation:     input.Operation,
		ClusterID:     input.ClusterID,
		KeyID:         input.KeyID,
		KeyVersion:    input.Version,
		Decision:      input.Decision,
		PolicyID:      input.PolicyID,
		Reason:        input.Reason,
	}
	if store != nil {
		if err := store.InsertAuditEvent(ctx, event); err != nil {
			return "", err
		}
	}
	if store == nil && strings.TrimSpace(auditPath) == "" {
		return auditID, nil
	}
	if strings.TrimSpace(auditPath) != "" {
		if err := broker.NewFileAuditSink(auditPath, false).Write(ctx, event); err != nil {
			return "", err
		}
	}
	return auditID, nil
}

func auditWithStatePath(ctx context.Context, statePath string, auditPath string, input auditInput) (string, error) {
	if strings.TrimSpace(statePath) == "" {
		return audit(ctx, nil, auditPath, input)
	}
	store, err := broker.OpenSQLiteStore(ctx, statePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = store.Close() }()
	return audit(ctx, store, auditPath, input)
}

type recoverySession struct {
	SchemaVersion     uint32 `json:"schema_version"`
	SessionID         string `json:"session_id"`
	RecoveryPackageID string `json:"recovery_package_id"`
	ClusterID         string `json:"cluster_id"`
	KeyID             string `json:"key_id"`
	SecretChecksum    string `json:"secret_checksum"`
	ExpiresAt         string `json:"expires_at"`
}

func (s recoverySession) Validate(metadata recovery.PackageMetadata, now time.Time) error {
	if s.SchemaVersion != 1 {
		return errors.New("unsupported recovery session schema version")
	}
	if s.RecoveryPackageID != metadata.PackageID || s.ClusterID != metadata.ClusterID || s.KeyID != metadata.KeyID {
		return errors.New("recovery session does not match package metadata")
	}
	if s.SecretChecksum != metadata.SecretChecksum {
		return errors.New("recovery session checksum mismatch")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, s.ExpiresAt)
	if err != nil {
		return fmt.Errorf("invalid recovery session expiry: %w", err)
	}
	if !now.Before(expiresAt) {
		return errors.New("recovery session expired")
	}
	return nil
}

type initOutput struct {
	AuditID             string                   `json:"audit_id"`
	RecoveryPackage     recovery.PackageMetadata `json:"recovery_package"`
	RecoveryPackagePath string                   `json:"recovery_package_path"`
	RecoveryShares      []string                 `json:"recovery_shares"`
	KeyringProfile      string                   `json:"keyring_profile"`
	SealConfig          string                   `json:"seal_config"`
}

type statusOutput struct {
	ClusterID   string `json:"cluster_id"`
	Ready       bool   `json:"ready"`
	ActiveKeyID string `json:"active_key_id"`
}

type enrollRequestOutput struct {
	AuditID   string `json:"audit_id"`
	RequestID string `json:"request_id"`
	Path      string `json:"path"`
}

type enrollGrantOutput struct {
	AuditID string `json:"audit_id"`
	GrantID string `json:"grant_id"`
	Path    string `json:"path"`
}

type enrollApplyOutput struct {
	AuditID        string `json:"audit_id"`
	GrantID        string `json:"grant_id"`
	SubjectID      string `json:"subject_id"`
	LocalStatePath string `json:"local_state_path"`
}

type recoverBeginOutput struct {
	AuditID     string `json:"audit_id"`
	SessionID   string `json:"session_id"`
	SessionPath string `json:"session_path"`
}

type recoverEnrollOutput struct {
	AuditID   string `json:"audit_id"`
	ClusterID string `json:"cluster_id"`
	KeyID     string `json:"key_id"`
	SubjectID string `json:"subject_id"`
}

type recoverFinishOutput struct {
	AuditID   string `json:"audit_id"`
	SessionID string `json:"session_id"`
}

type rotateOutput struct {
	AuditID       string                       `json:"audit_id,omitempty"`
	OperationID   string                       `json:"operation_id"`
	ClusterID     string                       `json:"cluster_id"`
	KeyID         string                       `json:"key_id"`
	FromVersion   uint32                       `json:"from_version"`
	ToVersion     uint32                       `json:"to_version"`
	Status        string                       `json:"status"`
	Verifications []rotationVerificationOutput `json:"verifications,omitempty"`
}

type rotateOpenBAORootOutput struct {
	AuditID      string                     `json:"audit_id"`
	OperationID  string                     `json:"operation_id"`
	ClusterID    string                     `json:"cluster_id"`
	KeyID        string                     `json:"key_id"`
	FromVersion  uint32                     `json:"from_version"`
	ToVersion    uint32                     `json:"to_version"`
	Status       string                     `json:"status"`
	Endpoint     string                     `json:"endpoint"`
	HTTPStatus   int                        `json:"http_status"`
	Verification rotationVerificationOutput `json:"verification"`
}

type rotateVerifyRestartOutput struct {
	AuditID            string                     `json:"audit_id"`
	OperationID        string                     `json:"operation_id"`
	ClusterID          string                     `json:"cluster_id"`
	KeyID              string                     `json:"key_id"`
	FromVersion        uint32                     `json:"from_version"`
	ToVersion          uint32                     `json:"to_version"`
	Status             string                     `json:"status"`
	Endpoint           string                     `json:"endpoint"`
	OpenBaoInitialized bool                       `json:"openbao_initialized"`
	OpenBaoSealed      bool                       `json:"openbao_sealed"`
	OpenBaoSealType    string                     `json:"openbao_seal_type"`
	Verification       rotationVerificationOutput `json:"verification"`
}

type rotationVerificationOutput struct {
	Name       string `json:"name"`
	Verified   bool   `json:"verified"`
	VerifiedAt string `json:"verified_at,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type revokeSubjectOutput struct {
	AuditID      string   `json:"audit_id"`
	ClusterID    string   `json:"cluster_id"`
	SubjectID    string   `json:"subject_id"`
	Revoked      bool     `json:"revoked"`
	Mode         string   `json:"mode"`
	RotationPlan string   `json:"rotation_plan,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

type revokeStatusOutput struct {
	ClusterID string `json:"cluster_id"`
	SubjectID string `json:"subject_id"`
	Revoked   bool   `json:"revoked"`
}

type tpmProvisionOutput struct {
	StatePath  string   `json:"state_path"`
	KeyID      string   `json:"key_id"`
	PolicyMode string   `json:"policy_mode"`
	Warnings   []string `json:"warnings"`
	SealConfig string   `json:"seal_config"`
}

type tpmStatusOutput struct {
	StatePath  string   `json:"state_path"`
	Ready      bool     `json:"ready"`
	KeyID      string   `json:"key_id"`
	PolicyMode string   `json:"policy_mode,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

type localTrustState struct {
	SchemaVersion     uint32   `json:"schema_version"`
	GrantID           string   `json:"grant_id"`
	RequestID         string   `json:"request_id"`
	ClusterID         string   `json:"cluster_id"`
	KeyID             string   `json:"key_id"`
	SubjectID         string   `json:"subject_id"`
	ApprovalMode      string   `json:"approval_mode"`
	AllowedOperations []string `json:"allowed_operations"`
	PolicyID          string   `json:"policy_id"`
	IssuerPublicKey   string   `json:"issuer_public_key"`
	AppliedAt         string   `json:"applied_at"`
	StatusCheckedAt   string   `json:"status_checked_at"`
}

func validateFormat(format string) error {
	switch format {
	case formatText, formatJSON:
		return nil
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported format %q", format))
	}
}

func validateKeyringProfile(profile string) error {
	switch strings.TrimSpace(profile) {
	case broker.DevelopmentProfile, "recovery-threshold", "broker-tpm":
		return nil
	default:
		return cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported keyring profile %q", profile))
	}
}

func validateApprovalMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "", approvalModeSingleOperator:
		return approvalModeSingleOperator, nil
	case approvalModeQuorum:
		return "", cli.WithExitCode(
			cli.ExitUsage,
			errors.New("quorum approval mode is reserved for a later policy implementation"),
		)
	default:
		return "", cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported approval mode %q", mode))
	}
}

func validateRevocationMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "", revocationModeBroker:
		return revocationModeBroker, nil
	case revocationModeLocalTPM:
		return revocationModeLocalTPM, nil
	default:
		return "", cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported revocation mode %q", mode))
	}
}

func revocationWarnings(mode string) []string {
	if mode != revocationModeLocalTPM {
		return nil
	}
	return []string{
		"local TPM revocation does not remove TPM-sealed key material",
		"rotate the wrapping key and assess old backups before treating the node as revoked",
	}
}

func parseOperations(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	operations := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		operation := strings.ToLower(strings.TrimSpace(part))
		if operation == "" {
			continue
		}
		switch operation {
		case "wrap", "unwrap":
		default:
			return nil, cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported operation %q", operation))
		}
		if _, ok := seen[operation]; ok {
			continue
		}
		seen[operation] = struct{}{}
		operations = append(operations, operation)
	}
	if len(operations) == 0 {
		return nil, cli.WithExitCode(cli.ExitUsage, errors.New("at least one operation is required"))
	}
	return operations, nil
}

func validateTPMPolicyMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case tpmlocal.PolicyModeTPMOnly, tpmlocal.PolicyModeSecureBoot:
		return mode, nil
	case tpmlocal.PolicyModeMeasured:
		return "", cli.WithExitCode(cli.ExitUsage, errors.New("measured TPM policy is reserved for later milestones"))
	default:
		return "", cli.WithExitCode(cli.ExitUsage, fmt.Errorf("unsupported TPM policy %q", mode))
	}
}

func parsePCRIndexes(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	pcrs := make([]int, 0, len(parts))
	seen := make(map[int]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pcr, err := strconv.Atoi(part)
		if err != nil {
			return nil, cli.WithExitCode(cli.ExitUsage, fmt.Errorf("invalid PCR index %q", part))
		}
		if pcr < 0 || pcr > 23 {
			return nil, cli.WithExitCode(cli.ExitUsage, fmt.Errorf("PCR index %d is out of range", pcr))
		}
		if _, ok := seen[pcr]; ok {
			continue
		}
		seen[pcr] = struct{}{}
		pcrs = append(pcrs, pcr)
	}
	if len(pcrs) == 0 {
		return nil, cli.WithExitCode(cli.ExitUsage, errors.New("at least one PCR index is required"))
	}
	return pcrs, nil
}

func parseKeyVersion(value uint) (uint32, error) {
	if value == 0 {
		return 0, cli.WithExitCode(cli.ExitUsage, errors.New("-key-version must be greater than zero"))
	}
	if value > math.MaxUint32 {
		return 0, cli.WithExitCode(cli.ExitUsage, errors.New("-key-version must fit in uint32"))
	}
	return uint32(value), nil
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

//nolint:forbidigo // JSON files are a reviewed CLI serialization boundary for typed command DTOs.
func writeJSONFile[T any](path string, value T) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	body, err := marshalStrict(value)
	if err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write temporary JSON file: %w", err)
	}
	if err := os.Chmod(temp, 0o600); err != nil {
		return fmt.Errorf("chmod temporary JSON file: %w", err)
	}
	if err := os.Rename(temp, path); err != nil {
		return fmt.Errorf("rename JSON file: %w", err)
	}
	return nil
}

//nolint:forbidigo // JSON files are a reviewed CLI deserialization boundary for typed command DTOs.
func readJSONFile[T any](path string, value *T) error {
	if err := rejectUnsafePermissions(path); err != nil {
		return err
	}
	// #nosec G304 -- path is operator supplied and permission-checked.
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read JSON file: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("parse JSON file: %w", err)
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("JSON file has trailing content")
	}
	return nil
}

func readSharesFile(path string) ([]string, error) {
	if err := rejectUnsafePermissions(path); err != nil {
		return nil, err
	}
	// #nosec G304 -- path is operator supplied and permission-checked.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read shares file: %w", err)
	}
	var shares []string
	if err := json.Unmarshal(raw, &shares); err == nil {
		return shares, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			shares = append(shares, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan shares file: %w", err)
	}
	return shares, nil
}

func rejectUnsafePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refusing to read %s with permissions %04o", path, info.Mode().Perm())
	}
	return nil
}

//nolint:forbidigo // JSON marshaling is a reviewed CLI serialization boundary for typed command DTOs.
func marshalStrict[T any](value T) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}
	return body, nil
}

func randomID(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(raw), nil
}

func sealConfigSnippet(clusterID string, keyID string) string {
	return fmt.Sprintf(`seal "attested-unseal" {
  cluster_id = %q
  key_id     = %q
}`, clusterID, keyID)
}

func localTPMSealConfigSnippet(ref keyring.KeyRef, statePath string, tpmDevice string) string {
	return fmt.Sprintf(`seal "attested-unseal" {
  mode        = "local-tpm"
  cluster_id  = %q
  key_id      = %q
  key_version = %q
  state_path  = %q
  tpm_device  = %q
}`, ref.ClusterID, ref.KeyID, strconv.FormatUint(uint64(ref.Version), 10), statePath, tpmDevice)
}

func printUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, "Operator CLI for OpenBao attested unseal lifecycle tasks.")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Usage:")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl init -state broker.db")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl status -state broker.db")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl enroll request -subject-id node-a -out request.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl enroll issue -state broker.db -request request.json -grant grant.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl enroll apply -state broker.db -grant grant.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl recover begin -package recovery.json -shares-file shares.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl recover enroll -state broker.db -package recovery.json \\")
	_, _ = fmt.Fprintln(out, "    -shares-file shares.json -session session.json -request target-request.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl recover finish -session session.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl rotate start -state broker.db")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl rotate activate -state broker.db -operation-id rot_...")
	_, _ = fmt.Fprintln(out, "  BAO_TOKEN=... bao-unsealctl rotate openbao-root -state broker.db -operation-id rot_...")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl rotate verify-restart -state broker.db -operation-id rot_...")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl revoke subject -state broker.db -subject-id node-a")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl tpm provision -state-path /var/lib/openbao-attested-unseal \\")
	_, _ = fmt.Fprintln(out, "    -package recovery.json -shares-file shares.json")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl tpm status -state-path /var/lib/openbao-attested-unseal")
	_, _ = fmt.Fprintln(out, "  bao-unsealctl version")
}

func printVersion(out io.Writer, info version.Info) {
	_, _ = fmt.Fprintf(out, "version: %s\n", info.Version)
	_, _ = fmt.Fprintf(out, "commit: %s\n", info.Commit)
	_, _ = fmt.Fprintf(out, "buildDate: %s\n", info.BuildDate)
	_, _ = fmt.Fprintf(out, "dirty: %s\n", info.Dirty)
}
