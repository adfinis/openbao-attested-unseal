package baounsealctl

import (
	"github.com/adfinis/openbao-attested-unseal/internal/brokeradmin"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc"
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
	return brokeradmin.DialOptions(brokeradmin.ClientOptions{
		Plaintext:      options.plaintext,
		CACertPath:     options.caCertPath,
		TLSServerName:  options.tlsServerName,
		ClientCertPath: options.clientCertPath,
		ClientKeyPath:  options.clientKeyPath,
	})
}

func requireAllowDecision(decision *protocolv1.PolicyDecision, operation string) error {
	return brokeradmin.RequireAllowDecision(decision, operation)
}

func policyDecisionMessage(decision *protocolv1.PolicyDecision, fallback string) string {
	return brokeradmin.DecisionMessage(decision, fallback)
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
	return brokeradmin.UnixSecondsOutput(value)
}

func nodeEvidenceStatusOutput(status protocolv1.NodeEvidenceStatus) string {
	return brokeradmin.NodeEvidenceStatusOutput(status)
}

func policyDecisionOutput(state protocolv1.PolicyDecisionState) string {
	return brokeradmin.PolicyDecisionOutput(state)
}
