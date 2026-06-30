package baounsealctl

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

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
