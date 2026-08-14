package broker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func (s AdminService) authorizeNodeEvidencePublisher(
	ctx context.Context,
	clusterID string,
	nodeName string,
	nodeUID string,
	provider string,
) (nodeevidence.Enrollment, string, protocolv1.ErrorCode, error) {
	if provider != nodeevidence.ProviderTPM2Quote {
		return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED, nil
	}
	certificateHash, err := nodeEvidenceClientCertificateHash(ctx)
	if err != nil {
		return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED, errors.New(
			"node evidence publisher requires an authenticated client certificate",
		)
	}
	if s.nodeEvidenceEnrollments == nil {
		return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_INTERNAL, errors.New(
			"node evidence enrollment storage is not configured",
		)
	}
	enrollment, err := s.nodeEvidenceEnrollments.ActiveNodeEvidenceEnrollment(ctx, clusterID, nodeName)
	if err != nil {
		if errors.Is(err, nodeevidence.ErrEnrollmentNotFound) ||
			errors.Is(err, nodeevidence.ErrEnrollmentRevoked) {
			return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, errors.New(
				"node TPM identity is not enrolled",
			)
		}
		return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_INTERNAL, errors.New(
			"node evidence enrollment lookup failed",
		)
	}
	if enrollment.Provider != provider ||
		subtle.ConstantTimeCompare([]byte(enrollment.NodeUID), []byte(nodeUID)) != 1 {
		return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, errors.New(
			"node TPM identity is not enrolled",
		)
	}
	if !enrollment.AuthorizesPublisher(certificateHash) {
		return nodeevidence.Enrollment{}, "", protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, errors.New(
			"node evidence publisher is not authorized for this node",
		)
	}
	return enrollment, certificateHash, protocolv1.ErrorCode_ERROR_CODE_UNSPECIFIED, nil
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
