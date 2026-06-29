package kmsplugin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	k8sprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/kubernetes"
	runtimeconfig "github.com/adfinis/openbao-attested-unseal/internal/config"
	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	developmentSubjectClaimNamespace = "dev"
	developmentSubjectClaimName      = "subject"
)

type brokerBackend struct {
	config Config
	conn   *grpc.ClientConn
	client protocolv1.UnsealServiceClient
}

func newBrokerBackend(ctx context.Context, config Config) (Backend, error) {
	options, err := brokerDialOptions(config)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(config.BrokerAddress, options...)
	if err != nil {
		return nil, fmt.Errorf("create broker client: %w", err)
	}
	backend := &brokerBackend{
		config: config,
		conn:   conn,
		client: protocolv1.NewUnsealServiceClient(conn),
	}
	if _, err := backend.Status(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return backend, nil
}

func (b *brokerBackend) Encrypt(ctx context.Context, req EncryptRequest) (EncryptResponse, error) {
	challenge, err := b.challenge(ctx, protocolv1.Operation_OPERATION_WRAP)
	if err != nil {
		return EncryptResponse{}, err
	}
	requested, err := requestedKeyFromString(req.KeyID)
	if err != nil {
		return EncryptResponse{}, err
	}
	evidence, err := b.evidence(challenge.GetChallengeId())
	if err != nil {
		return EncryptResponse{}, err
	}
	resp, err := b.client.Wrap(ctx, &protocolv1.WrapRequest{
		RequestedKey: requested,
		Plaintext:    req.Plaintext,
		Aad:          req.AAD,
		Evidence:     evidence,
	})
	if err != nil {
		return EncryptResponse{}, fmt.Errorf("broker wrap call failed: %w", err)
	}
	if err := requireAllow(resp.GetDecision(), "broker wrap denied"); err != nil {
		return EncryptResponse{}, err
	}
	return EncryptResponse{Blob: protoToBlobInfo(resp.GetBlob())}, nil
}

func (b *brokerBackend) Decrypt(ctx context.Context, req DecryptRequest) (DecryptResponse, error) {
	if err := validateDecryptRequestKey(req.KeyID, req.Blob); err != nil {
		return DecryptResponse{}, err
	}
	challenge, err := b.challenge(ctx, protocolv1.Operation_OPERATION_UNWRAP)
	if err != nil {
		return DecryptResponse{}, err
	}
	evidence, err := b.evidence(challenge.GetChallengeId())
	if err != nil {
		return DecryptResponse{}, err
	}
	resp, err := b.client.Unwrap(ctx, &protocolv1.UnwrapRequest{
		Blob:     blobInfoToProto(req.Blob),
		Aad:      req.AAD,
		Evidence: evidence,
	})
	if err != nil {
		return DecryptResponse{}, fmt.Errorf("broker unwrap call failed: %w", err)
	}
	if err := requireAllow(resp.GetDecision(), "broker unwrap denied"); err != nil {
		return DecryptResponse{}, err
	}
	return DecryptResponse{Plaintext: resp.GetPlaintext()}, nil
}

func (b *brokerBackend) KeyID(ctx context.Context) (string, error) {
	status, err := b.Status(ctx)
	if err != nil {
		return "", err
	}
	if status.KeyID == "" {
		return "", fmt.Errorf("%w: broker active key is empty", ErrBackendUnavailable)
	}
	return status.KeyID, nil
}

func (b *brokerBackend) Status(ctx context.Context) (BackendStatus, error) {
	resp, err := b.client.Status(ctx, &protocolv1.StatusRequest{ClusterId: b.config.ClusterID})
	if err != nil {
		return BackendStatus{}, fmt.Errorf("broker status call failed: %w", err)
	}
	if !resp.GetReady() {
		return BackendStatus{
			Ready: false,
			KeyID: resp.GetActiveKeyId(),
			Mode:  b.config.Mode,
		}, brokerErrors("broker is not ready", resp.GetErrors())
	}
	return BackendStatus{
		Ready: true,
		KeyID: resp.GetActiveKeyId(),
		Mode:  b.config.Mode,
	}, nil
}

func (b *brokerBackend) Close(context.Context) error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *brokerBackend) challenge(
	ctx context.Context,
	operation protocolv1.Operation,
) (*protocolv1.ChallengeResponse, error) {
	challenge, err := b.client.Challenge(ctx, &protocolv1.ChallengeRequest{
		ClusterId: b.config.ClusterID,
		NodeId:    b.config.NodeID,
		Operation: operation,
	})
	if err != nil {
		return nil, fmt.Errorf("broker challenge call failed: %w", err)
	}
	if challenge.GetChallengeId() == "" {
		return nil, fmt.Errorf("%w: broker challenge response is missing challenge_id", ErrBackendUnavailable)
	}
	return challenge, nil
}

func (b *brokerBackend) evidence(challengeID string) (*protocolv1.EvidenceEnvelope, error) {
	switch b.config.BrokerEvidenceMode() {
	case EvidenceModeDevelopmentSubject:
		return &protocolv1.EvidenceEnvelope{
			Provider:    protocolv1.AttestationProvider_ATTESTATION_PROVIDER_UNSPECIFIED,
			Format:      "development-subject",
			ChallengeId: challengeID,
			NormalizedClaims: []*protocolv1.Claim{
				{
					Namespace: developmentSubjectClaimNamespace,
					Name:      developmentSubjectClaimName,
					Value:     b.config.NodeID,
				},
			},
		}, nil
	case EvidenceModeKubernetesWorkload:
		token, err := readKubernetesWorkloadToken(b.config.KubernetesTokenFile)
		if err != nil {
			return nil, err
		}
		return k8sprovider.NewEvidenceEnvelope(challengeID, token)
	default:
		return nil, fmt.Errorf("%w: unsupported evidence mode %q", ErrBackendUnavailable, b.config.BrokerEvidenceMode())
	}
}

func readKubernetesWorkloadToken(path string) (string, error) {
	path = runtimeconfig.KubernetesBearerTokenFile(path)
	// #nosec G304 -- Kubernetes token path is operator supplied plugin configuration.
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

func brokerDialOptions(config Config) ([]grpc.DialOption, error) {
	if config.BrokerPlaintext {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: config.BrokerTLSServerName,
	}
	if config.BrokerCACertPath != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		// #nosec G304 -- broker CA path is operator supplied plugin configuration.
		caPEM, err := os.ReadFile(config.BrokerCACertPath)
		if err != nil {
			return nil, fmt.Errorf("read broker CA certificate: %w", err)
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("broker CA certificate did not contain a PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if config.BrokerClientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(config.BrokerClientCertPath, config.BrokerClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load broker client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))}, nil
}

func requestedKeyFromString(raw string) (*protocolv1.KeyRef, error) {
	if raw == "" {
		return nil, nil
	}
	ref, err := keyring.ParseKeyRef(raw)
	if err != nil {
		return nil, err
	}
	return &protocolv1.KeyRef{
		ClusterId: ref.ClusterID,
		KeyId:     ref.KeyID,
		Version:   ref.Version,
	}, nil
}

func validateDecryptRequestKey(keyID string, blob *wrapping.BlobInfo) error {
	if keyID == "" {
		return nil
	}
	if blob == nil || blob.GetKeyInfo() == nil {
		return fmt.Errorf("%w: missing blob key info", keyring.ErrInvalidMetadata)
	}
	if keyID != blob.GetKeyInfo().GetKeyId() {
		return fmt.Errorf(
			"%w: requested key %q does not match blob key %q",
			keyring.ErrInvalidMetadata,
			keyID,
			blob.GetKeyInfo().GetKeyId(),
		)
	}
	return nil
}

func blobInfoToProto(blob *wrapping.BlobInfo) *protocolv1.WrappedBlob {
	if blob == nil || blob.GetKeyInfo() == nil {
		return &protocolv1.WrappedBlob{}
	}
	ref, err := keyring.ParseKeyRef(blob.GetKeyInfo().GetKeyId())
	if err != nil {
		return &protocolv1.WrappedBlob{}
	}
	return &protocolv1.WrappedBlob{
		Ciphertext: blob.GetCiphertext(),
		Iv:         blob.GetIv(),
		Key: &protocolv1.KeyRef{
			ClusterId: ref.ClusterID,
			KeyId:     ref.KeyID,
			Version:   ref.Version,
		},
		Mechanism: blob.GetKeyInfo().GetMechanism(),
	}
}

func protoToBlobInfo(blob *protocolv1.WrappedBlob) *wrapping.BlobInfo {
	if blob == nil || blob.GetKey() == nil {
		return &wrapping.BlobInfo{}
	}
	ref := keyring.KeyRef{
		ClusterID: blob.GetKey().GetClusterId(),
		KeyID:     blob.GetKey().GetKeyId(),
		Version:   blob.GetKey().GetVersion(),
	}
	return &wrapping.BlobInfo{
		Ciphertext: blob.GetCiphertext(),
		Iv:         blob.GetIv(),
		KeyInfo: &wrapping.KeyInfo{
			Mechanism: blob.GetMechanism(),
			KeyId:     ref.String(),
		},
	}
}

func requireAllow(decision *protocolv1.PolicyDecision, fallback string) error {
	if decision.GetState() == protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		return nil
	}
	return brokerErrors(fallback, decision.GetErrors())
}

func brokerErrors(fallback string, brokerErrs []*protocolv1.BrokerError) error {
	if len(brokerErrs) == 0 {
		return fmt.Errorf("%w: %s", ErrBackendUnavailable, fallback)
	}
	first := brokerErrs[0]
	return fmt.Errorf("%w: %s: %s", ErrBackendUnavailable, first.GetCode().String(), first.GetMessage())
}
