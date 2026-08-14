package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func (s AdminService) authorizeNodeEvidencePublisher(
	ctx context.Context,
	nodeName string,
	provider string,
) (string, protocolv1.ErrorCode, error) {
	if provider != nodeevidence.ProviderTPM2Quote {
		return "", protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED, nil
	}
	certificateHash, err := nodeEvidenceClientCertificateHash(ctx)
	if err != nil {
		return "", protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, errors.New(
			"node evidence publisher requires an authenticated client certificate",
		)
	}
	publisher, ok := s.nodeEvidencePublishers[certificateHash]
	if !ok || !slices.Contains(publisher.NodeNames, nodeName) {
		return "", protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, errors.New(
			"node evidence publisher is not authorized for this node",
		)
	}
	return certificateHash, protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED, nil
}

func nodeEvidenceClientCertificateHash(ctx context.Context) (string, error) {
	remote, ok := peer.FromContext(ctx)
	if !ok || remote.AuthInfo == nil {
		return "", errors.New("peer authentication is unavailable")
	}
	tlsInfo, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", errors.New("peer certificate is unavailable")
	}
	digest := sha256.Sum256(tlsInfo.State.PeerCertificates[0].Raw)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func canonicalSHA256Digest(value string) (string, error) {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("SHA-256 digest prefix is required")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(raw) != sha256.Size {
		return "", errors.New("SHA-256 digest must contain 32 bytes")
	}
	canonical := prefix + hex.EncodeToString(raw)
	if subtle.ConstantTimeCompare([]byte(canonical), []byte(value)) != 1 {
		return "", fmt.Errorf("SHA-256 digest is not canonical")
	}
	return canonical, nil
}
