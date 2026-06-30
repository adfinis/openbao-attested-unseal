package baounsealctl

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/cli"
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
