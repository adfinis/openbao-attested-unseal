package broker

import (
	"context"
	"fmt"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/keyring"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/grpc/peer"
)

// Service implements the broker gRPC API.
type Service struct {
	protocolv1.UnimplementedUnsealServiceServer
	store     Store
	audit     *FileAuditSink
	policy    *PolicyEngine
	telemetry *Telemetry
	verifier  EvidenceVerifier
	config    Config
	clock     func() time.Time
}

// NewService creates the gRPC service implementation.
func NewService(config Config, store Store, audit *FileAuditSink, telemetry *Telemetry) *Service {
	return &Service{
		store:     store,
		audit:     audit,
		policy:    NewPolicyEngine(store, config.Policy(), telemetry),
		telemetry: telemetry,
		verifier:  DevelopmentEvidenceVerifier{},
		config:    config,
		clock:     time.Now,
	}
}

// NewServiceWithEvidenceVerifier creates a service with an injected evidence verifier.
func NewServiceWithEvidenceVerifier(
	config Config,
	store Store,
	audit *FileAuditSink,
	telemetry *Telemetry,
	verifier EvidenceVerifier,
) *Service {
	service := NewService(config, store, audit, telemetry)
	if verifier != nil {
		service.verifier = verifier
	}
	return service
}

// NewServiceWithEvidenceVerifierAndNodeEvidence creates a service with verifier and node evidence dependencies.
func NewServiceWithEvidenceVerifierAndNodeEvidence(
	config Config,
	store Store,
	audit *FileAuditSink,
	telemetry *Telemetry,
	verifier EvidenceVerifier,
	nodeEvidence NodeEvidenceReader,
) *Service {
	service := NewServiceWithEvidenceVerifier(config, store, audit, telemetry, verifier)
	service.policy.nodeEvidence = nodeEvidence
	return service
}

// Challenge creates a single-use broker challenge.
func (s *Service) Challenge(
	ctx context.Context,
	req *protocolv1.ChallengeRequest,
) (*protocolv1.ChallengeResponse, error) {
	ctx, span := s.telemetry.start(ctx, "broker.challenge")
	defer span.End()

	if req == nil {
		return nil, fmt.Errorf("challenge request is required")
	}
	if req.GetClusterId() == "" || req.GetNodeId() == "" {
		return nil, fmt.Errorf("cluster_id and node_id are required")
	}
	now := s.clock()
	challengeID, err := randomID("chal")
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	expiresAt := now.Add(s.config.ChallengeTTL())
	challenge := Challenge{
		ID:        challengeID,
		Nonce:     nonce,
		ClusterID: req.GetClusterId(),
		Subject:   req.GetNodeId(),
		Operation: req.GetOperation(),
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}
	if err := s.store.CreateChallenge(ctx, challenge); err != nil {
		return nil, err
	}
	decision := Allow(s.config.Policy())
	attrs := safeAttributes(
		req.GetClusterId(),
		"",
		0,
		req.GetOperation(),
		decision,
		auditIDFromRequest(req.GetAudit()),
	)
	s.telemetry.recordChallenge(ctx, attrs)
	s.telemetry.recordAttestationPlaceholder(ctx, attrs)
	return &protocolv1.ChallengeResponse{
		ChallengeId:        challengeID,
		Nonce:              nonce,
		ExpiresUnixSeconds: expiresAt.Unix(),
	}, nil
}

// Wrap wraps OpenBao seal plaintext with the active development keyring.
func (s *Service) Wrap(
	ctx context.Context,
	req *protocolv1.WrapRequest,
) (*protocolv1.WrapResponse, error) {
	ctx, span := s.telemetry.start(ctx, "broker.wrap")
	defer span.End()

	if req == nil {
		return &protocolv1.WrapResponse{
			Decision: Deny(
				s.config.Policy(),
				protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"wrap request is required",
			).Proto(),
		}, nil
	}
	verified, evidenceDecision := s.evidenceSubject(ctx, req.GetEvidence())
	subject := verified.Subject
	if !evidenceDecision.Allowed() {
		s.auditDecision(
			ctx,
			subject,
			protocolv1.Operation_OPERATION_WRAP,
			s.config.ClusterID,
			keyRefView{},
			evidenceDecision,
			req.GetEvidence(),
		)
		return &protocolv1.WrapResponse{Decision: evidenceDecision.Proto()}, nil
	}
	ref, decision := s.wrapKeyRef(ctx, req.GetRequestedKey())
	if !decision.Allowed() {
		s.auditDecision(
			ctx,
			subject,
			protocolv1.Operation_OPERATION_WRAP,
			s.config.ClusterID,
			keyRefView{},
			decision,
			req.GetEvidence(),
		)
		s.telemetry.recordWrap(ctx, safeAttributes(
			s.config.ClusterID,
			"",
			0,
			protocolv1.Operation_OPERATION_WRAP,
			decision,
			"",
		))
		return &protocolv1.WrapResponse{Decision: decision.Proto()}, nil
	}
	decision = s.evaluate(ctx, policyRequest{
		ClusterID:   ref.ClusterID,
		Subject:     subject,
		Workload:    verified.Workload,
		Operation:   protocolv1.Operation_OPERATION_WRAP,
		ChallengeID: req.GetEvidence().GetChallengeId(),
		KeyRef:      ref,
	})
	if !decision.Allowed() {
		s.auditDecision(
			ctx,
			subject,
			protocolv1.Operation_OPERATION_WRAP,
			ref.ClusterID,
			keyRefView{KeyID: ref.KeyID, Version: ref.Version},
			decision,
			req.GetEvidence(),
		)
		s.telemetry.recordWrap(ctx, safeAttributes(
			ref.ClusterID,
			ref.KeyID,
			ref.Version,
			protocolv1.Operation_OPERATION_WRAP,
			decision,
			"",
		))
		return &protocolv1.WrapResponse{Decision: decision.Proto()}, nil
	}

	attrs := safeAttributes(
		ref.ClusterID,
		ref.KeyID,
		ref.Version,
		protocolv1.Operation_OPERATION_WRAP,
		decision,
		"",
	)
	ctx, keyringSpan := s.telemetry.start(ctx, "broker.keyring.wrap", attrs...)
	started := time.Now()
	ring, err := s.store.LoadKeyring(ctx, ref.ClusterID)
	if err != nil {
		keyringSpan.End()
		decision = Deny(s.config.Policy(), protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "keyring load failed")
		return &protocolv1.WrapResponse{Decision: decision.Proto()}, nil
	}
	blob, err := ring.Encrypt(ctx, req.GetPlaintext(), req.GetAad())
	keyringSpan.End()
	s.telemetry.recordKeyringLatency(ctx, started, attrs)
	if err != nil {
		decision = Deny(s.config.Policy(), protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "wrap failed")
		return &protocolv1.WrapResponse{Decision: decision.Proto()}, nil
	}
	event := s.auditDecision(
		ctx,
		subject,
		protocolv1.Operation_OPERATION_WRAP,
		ref.ClusterID,
		keyRefView{KeyID: ref.KeyID, Version: ref.Version},
		decision,
		req.GetEvidence(),
	)
	s.telemetry.recordWrap(ctx, safeAttributes(
		ref.ClusterID,
		ref.KeyID,
		ref.Version,
		protocolv1.Operation_OPERATION_WRAP,
		decision,
		event.AuditID,
	))
	return &protocolv1.WrapResponse{Blob: wrappedBlobToProto(blob), Decision: decision.Proto()}, nil
}

// Unwrap unwraps OpenBao seal ciphertext.
func (s *Service) Unwrap(
	ctx context.Context,
	req *protocolv1.UnwrapRequest,
) (*protocolv1.UnwrapResponse, error) {
	ctx, span := s.telemetry.start(ctx, "broker.unwrap")
	defer span.End()

	if req == nil {
		return &protocolv1.UnwrapResponse{
			Decision: Deny(
				s.config.Policy(),
				protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"unwrap request is required",
			).Proto(),
		}, nil
	}
	verified, evidenceDecision := s.evidenceSubject(ctx, req.GetEvidence())
	subject := verified.Subject
	if !evidenceDecision.Allowed() {
		s.auditDecision(
			ctx,
			subject,
			protocolv1.Operation_OPERATION_UNWRAP,
			s.config.ClusterID,
			keyRefView{},
			evidenceDecision,
			req.GetEvidence(),
		)
		return &protocolv1.UnwrapResponse{Decision: evidenceDecision.Proto()}, nil
	}
	ref, err := keyRefFromProto(req.GetBlob().GetKey())
	if err != nil {
		decision := Deny(s.config.Policy(), protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST, "blob key reference is invalid")
		s.auditDecision(
			ctx,
			subject,
			protocolv1.Operation_OPERATION_UNWRAP,
			s.config.ClusterID,
			keyRefView{},
			decision,
			req.GetEvidence(),
		)
		return &protocolv1.UnwrapResponse{Decision: decision.Proto()}, nil
	}
	decision := s.evaluate(ctx, policyRequest{
		ClusterID:   ref.ClusterID,
		Subject:     subject,
		Workload:    verified.Workload,
		Operation:   protocolv1.Operation_OPERATION_UNWRAP,
		ChallengeID: req.GetEvidence().GetChallengeId(),
		KeyRef:      ref,
	})
	if !decision.Allowed() {
		s.auditDecision(
			ctx,
			subject,
			protocolv1.Operation_OPERATION_UNWRAP,
			ref.ClusterID,
			keyRefView{KeyID: ref.KeyID, Version: ref.Version},
			decision,
			req.GetEvidence(),
		)
		s.telemetry.recordUnwrap(ctx, safeAttributes(
			ref.ClusterID,
			ref.KeyID,
			ref.Version,
			protocolv1.Operation_OPERATION_UNWRAP,
			decision,
			"",
		))
		return &protocolv1.UnwrapResponse{Decision: decision.Proto()}, nil
	}

	attrs := safeAttributes(
		ref.ClusterID,
		ref.KeyID,
		ref.Version,
		protocolv1.Operation_OPERATION_UNWRAP,
		decision,
		"",
	)
	ctx, keyringSpan := s.telemetry.start(ctx, "broker.keyring.unwrap", attrs...)
	started := time.Now()
	ring, err := s.store.LoadKeyring(ctx, ref.ClusterID)
	if err != nil {
		keyringSpan.End()
		decision = Deny(s.config.Policy(), protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "keyring load failed")
		return &protocolv1.UnwrapResponse{Decision: decision.Proto()}, nil
	}
	plaintext, err := ring.Decrypt(ctx, protoToBlobInfo(req.GetBlob()), req.GetAad())
	keyringSpan.End()
	s.telemetry.recordKeyringLatency(ctx, started, attrs)
	if err != nil {
		decision = Deny(s.config.Policy(), protocolv1.ErrorCode_ERROR_CODE_INTERNAL, "unwrap failed")
		return &protocolv1.UnwrapResponse{Decision: decision.Proto()}, nil
	}
	event := s.auditDecision(
		ctx,
		subject,
		protocolv1.Operation_OPERATION_UNWRAP,
		ref.ClusterID,
		keyRefView{KeyID: ref.KeyID, Version: ref.Version},
		decision,
		req.GetEvidence(),
	)
	s.telemetry.recordUnwrap(ctx, safeAttributes(
		ref.ClusterID,
		ref.KeyID,
		ref.Version,
		protocolv1.Operation_OPERATION_UNWRAP,
		decision,
		event.AuditID,
	))
	return &protocolv1.UnwrapResponse{Plaintext: plaintext, Decision: decision.Proto()}, nil
}

// Status reports broker readiness and configured key versions.
func (s *Service) Status(ctx context.Context, req *protocolv1.StatusRequest) (*protocolv1.StatusResponse, error) {
	clusterID := s.config.ClusterID
	if req != nil && req.GetClusterId() != "" {
		clusterID = req.GetClusterId()
	}
	ring, err := s.store.LoadKeyring(ctx, clusterID)
	if err != nil {
		return &protocolv1.StatusResponse{
			Ready: false,
			Errors: []*protocolv1.BrokerError{
				{Code: protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_USABLE, Message: "keyring is not ready"},
			},
		}, nil
	}
	active, err := ring.Active(ctx)
	if err != nil {
		return &protocolv1.StatusResponse{
			Ready: false,
			Errors: []*protocolv1.BrokerError{
				{
					Code:    protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_USABLE,
					Message: "active key is unavailable",
				},
			},
		}, nil
	}
	s.telemetry.recordKeyringUnlocked(ctx, safeAttributes(
		clusterID,
		active.Ref.KeyID,
		active.Ref.Version,
		protocolv1.Operation_OPERATION_UNSPECIFIED,
		Allow(s.config.Policy()),
		"",
	))
	return &protocolv1.StatusResponse{
		Ready:       true,
		ActiveKeyId: active.Ref.String(),
		Keys: []*protocolv1.KeyVersion{
			{
				Ref: &protocolv1.KeyRef{
					ClusterId: active.Ref.ClusterID,
					KeyId:     active.Ref.KeyID,
					Version:   active.Ref.Version,
				},
				Status:    protocolv1.KeyStatus_KEY_STATUS_ACTIVE,
				Algorithm: string(active.Algorithm),
				PolicyId:  active.PolicyID,
			},
		},
	}, nil
}

func (s *Service) wrapKeyRef(
	ctx context.Context,
	requested *protocolv1.KeyRef,
) (keyring.KeyRef, PolicyDecision) {
	if requested != nil && requested.GetVersion() != 0 {
		ref, err := keyRefFromProto(requested)
		if err != nil {
			return keyring.KeyRef{}, Deny(
				s.config.Policy(),
				protocolv1.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"requested key reference is invalid",
			)
		}
		return ref, Allow(s.config.Policy())
	}
	ring, err := s.store.LoadKeyring(ctx, s.config.ClusterID)
	if err != nil {
		return keyring.KeyRef{}, Deny(
			s.config.Policy(),
			protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_USABLE,
			"active key is unavailable",
		)
	}
	active, err := ring.Active(ctx)
	if err != nil {
		return keyring.KeyRef{}, Deny(
			s.config.Policy(),
			protocolv1.ErrorCode_ERROR_CODE_KEY_NOT_USABLE,
			"active key is unavailable",
		)
	}
	return active.Ref, Allow(s.config.Policy())
}

func (s *Service) evaluate(ctx context.Context, req policyRequest) PolicyDecision {
	ctx, span := s.telemetry.start(ctx, "broker.policy.evaluate")
	defer span.End()
	started := time.Now()
	decision := s.policy.evaluate(ctx, req)
	attrs := safeAttributes(
		req.ClusterID,
		req.KeyRef.KeyID,
		req.KeyRef.Version,
		req.Operation,
		decision,
		"",
	)
	span.SetAttributes(attrs...)
	s.telemetry.recordPolicyLatency(ctx, started, attrs)
	return decision
}

func (s *Service) evidenceSubject(
	ctx context.Context,
	evidence *protocolv1.EvidenceEnvelope,
) (VerifiedEvidence, PolicyDecision) {
	verifier := s.verifier
	if verifier == nil {
		verifier = DevelopmentEvidenceVerifier{}
	}
	verified, err := verifier.VerifyEvidence(ctx, evidence)
	if err != nil {
		return VerifiedEvidence{}, Deny(
			s.config.Policy(),
			protocolv1.ErrorCode_ERROR_CODE_ATTESTATION_FAILED,
			"attestation verification failed",
		)
	}
	return verified, Allow(s.config.Policy())
}

func (s *Service) auditDecision(
	ctx context.Context,
	subject string,
	operation protocolv1.Operation,
	clusterID string,
	ref keyRefView,
	decision PolicyDecision,
	evidence *protocolv1.EvidenceEnvelope,
) AuditEvent {
	ctx, span := s.telemetry.start(ctx, "broker.audit.write")
	defer span.End()
	event, err := newAuditEvent(
		s.clock(),
		subject,
		operation,
		clusterID,
		ref,
		decision,
		evidence,
		remoteAddress(ctx),
	)
	if err != nil {
		s.telemetry.recordAuditFailure(ctx, safeAttributes(clusterID, ref.KeyID, ref.Version, operation, decision, ""))
		return AuditEvent{}
	}
	if err := s.store.InsertAuditEvent(ctx, event); err != nil {
		s.telemetry.recordAuditFailure(ctx, safeAttributes(
			clusterID,
			ref.KeyID,
			ref.Version,
			operation,
			decision,
			event.AuditID,
		))
	}
	if err := s.audit.Write(ctx, event); err != nil {
		s.telemetry.recordAuditFailure(ctx, safeAttributes(
			clusterID,
			ref.KeyID,
			ref.Version,
			operation,
			decision,
			event.AuditID,
		))
	}
	return event
}

func wrappedBlobToProto(blob *wrapping.BlobInfo) *protocolv1.WrappedBlob {
	ref, err := keyring.ParseKeyRef(blob.GetKeyInfo().GetKeyId())
	if err != nil {
		return nil
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

func remoteAddress(ctx context.Context) string {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo.Addr == nil {
		return ""
	}
	return peerInfo.Addr.String()
}

func auditIDFromRequest(audit *protocolv1.AuditContext) string {
	if audit == nil {
		return ""
	}
	if audit.GetCorrelationId() != "" {
		return audit.GetCorrelationId()
	}
	return audit.GetRequestId()
}

// EnrollmentStub reports M3 enrollment availability.
type EnrollmentStub struct {
	protocolv1.UnimplementedEnrollmentServiceServer
}

// Status reports that brokered enrollment is available through bao-unsealctl.
func (EnrollmentStub) Status(
	context.Context,
	*protocolv1.EnrollmentStatusRequest,
) (*protocolv1.EnrollmentStatusResponse, error) {
	return &protocolv1.EnrollmentStatusResponse{
		Implemented: true,
		Message:     "brokered enrollment is available through bao-unsealctl",
	}, nil
}

// RecoveryStub reports M3 recovery availability.
type RecoveryStub struct {
	protocolv1.UnimplementedRecoveryServiceServer
}

// Status reports that recovery enrollment is available through bao-unsealctl.
func (RecoveryStub) Status(
	context.Context,
	*protocolv1.RecoveryStatusRequest,
) (*protocolv1.RecoveryStatusResponse, error) {
	return &protocolv1.RecoveryStatusResponse{
		Implemented: true,
		Message:     "recovery enrollment is available through bao-unsealctl",
	}, nil
}

// AdminStub defines but does not implement admin APIs beyond status.
type AdminStub struct {
	protocolv1.UnimplementedAdminServiceServer
}

// Status reports that admin APIs are intentionally not implemented in M2.
func (AdminStub) Status(context.Context, *protocolv1.AdminStatusRequest) (*protocolv1.AdminStatusResponse, error) {
	return &protocolv1.AdminStatusResponse{
		Implemented: false,
		Message:     "admin APIs are not implemented in milestone 2",
	}, nil
}
