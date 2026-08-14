package broker

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestAdminServiceVerifiesEnrolledTPMNodeEvidenceAndRejectsReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 11, 15, 0, 0, 0, time.UTC)
	key, public := syntheticNodeEvidenceAK(t)
	cache := NewMemoryNodeEvidenceCache()
	ctx := nodeEvidencePublisherTestContext(t, []byte("node-a-publisher-certificate"))
	publisherHash, err := nodeEvidenceClientCertificateHash(ctx)
	if err != nil {
		t.Fatalf("nodeEvidenceClientCertificateHash returned error: %v", err)
	}
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 cache,
		challengeStore:               NewMemoryChallengeStore(),
		policyID:                     "development",
		nodeEvidencePublishProviders: []string{nodeevidence.ProviderTPM2Quote},
		nodeEvidenceTPMPolicies: map[string]TPMNodeEvidencePolicy{
			testNodeName: {
				NodeUID: fixtureNodeUID,
				Policy: tpmlocal.Policy{
					Mode:                 tpmlocal.PolicyModeTPMOnly,
					EnrolledAKPublicHash: tpmlocal.PublicDigest(public),
				},
			},
		},
		nodeEvidencePublishers: map[string]NodeEvidencePublisher{
			publisherHash: {NodeNames: []string{testNodeName}},
		},
		challengeTTL:    time.Minute,
		nodeEvidenceTTL: 30 * time.Second,
	})
	service.clock = func() time.Time { return now }

	challenge, err := service.ChallengeNodeEvidence(ctx, &protocolv1.NodeEvidenceChallengeRequest{
		ClusterId:  "prod-eu1",
		NodeName:   testNodeName,
		NodeUid:    fixtureNodeUID,
		ProviderId: nodeevidence.ProviderTPM2Quote,
	})
	if err != nil {
		t.Fatalf("ChallengeNodeEvidence returned error: %v", err)
	}
	if challenge.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("challenge decision = %s, want allow", challenge.GetDecision().GetState())
	}
	payload, err := syntheticNodeTPMEvidence(
		t,
		key,
		public,
		challenge.GetChallengeId(),
		challenge.GetNonce(),
	).Marshal()
	if err != nil {
		t.Fatalf("Marshal evidence returned error: %v", err)
	}
	request := &protocolv1.NodeEvidencePublishRequest{
		Submission: &protocolv1.NodeEvidenceSubmission{
			ClusterId:           "prod-eu1",
			NodeName:            testNodeName,
			NodeUid:             fixtureNodeUID,
			ProviderId:          nodeevidence.ProviderTPM2Quote,
			Format:              tpmlocal.EvidenceFormat,
			Payload:             payload,
			ChallengeId:         challenge.GetChallengeId(),
			RequestedTtlSeconds: 300,
		},
	}
	publish, err := service.PublishNodeEvidence(ctx, request)
	if err != nil {
		t.Fatalf("PublishNodeEvidence returned error: %v", err)
	}
	if publish.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("publish decision = %#v, want allow", publish.GetDecision())
	}
	if publish.GetEvidence().GetEvidenceHash() != nodeEvidencePayloadHash(payload) {
		t.Fatalf("evidence hash = %q, want broker payload hash", publish.GetEvidence().GetEvidenceHash())
	}
	if got := time.Unix(publish.GetEvidence().GetExpiresUnixSeconds(), 0).UTC(); !got.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("evidence expiry = %s, want broker TTL cap", got)
	}
	stored, err := cache.NodeEvidence(ctx, "prod-eu1", testNodeName)
	if err != nil {
		t.Fatalf("NodeEvidence returned error: %v", err)
	}
	if stored.NodeUID != fixtureNodeUID || stored.Provider != nodeevidence.ProviderTPM2Quote {
		t.Fatalf("stored evidence = %#v, want enrolled node projection", stored)
	}

	replay, err := service.PublishNodeEvidence(ctx, request)
	if err != nil {
		t.Fatalf("replayed PublishNodeEvidence returned error: %v", err)
	}
	if replay.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY ||
		replay.GetDecision().GetErrors()[0].GetCode() != protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("replay decision = %#v, want permission denied", replay.GetDecision())
	}
}

func TestAdminServiceBindsTPMChallengeToPublisherCertificate(t *testing.T) {
	t.Parallel()
	key, public := syntheticNodeEvidenceAK(t)
	firstCtx := nodeEvidencePublisherTestContext(t, []byte("first-publisher-certificate"))
	secondCtx := nodeEvidencePublisherTestContext(t, []byte("second-publisher-certificate"))
	firstHash, err := nodeEvidenceClientCertificateHash(firstCtx)
	if err != nil {
		t.Fatalf("first certificate hash error: %v", err)
	}
	secondHash, err := nodeEvidenceClientCertificateHash(secondCtx)
	if err != nil {
		t.Fatalf("second certificate hash error: %v", err)
	}
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 NewMemoryNodeEvidenceCache(),
		challengeStore:               NewMemoryChallengeStore(),
		nodeEvidencePublishProviders: []string{nodeevidence.ProviderTPM2Quote},
		nodeEvidenceTPMPolicies: map[string]TPMNodeEvidencePolicy{
			testNodeName: {
				NodeUID: fixtureNodeUID,
				Policy: tpmlocal.Policy{
					Mode:                 tpmlocal.PolicyModeTPMOnly,
					EnrolledAKPublicHash: tpmlocal.PublicDigest(public),
				},
			},
		},
		nodeEvidencePublishers: map[string]NodeEvidencePublisher{
			firstHash:  {NodeNames: []string{testNodeName}},
			secondHash: {NodeNames: []string{testNodeName}},
		},
	})
	challenge, err := service.ChallengeNodeEvidence(firstCtx, &protocolv1.NodeEvidenceChallengeRequest{
		ClusterId:  "prod-eu1",
		NodeName:   testNodeName,
		NodeUid:    fixtureNodeUID,
		ProviderId: nodeevidence.ProviderTPM2Quote,
	})
	if err != nil || challenge.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_ALLOW {
		t.Fatalf("ChallengeNodeEvidence = %#v, %v, want allow", challenge, err)
	}
	payload, err := syntheticNodeTPMEvidence(
		t,
		key,
		public,
		challenge.GetChallengeId(),
		challenge.GetNonce(),
	).Marshal()
	if err != nil {
		t.Fatalf("Marshal evidence returned error: %v", err)
	}
	stolen, err := service.PublishNodeEvidence(secondCtx, &protocolv1.NodeEvidencePublishRequest{
		Submission: &protocolv1.NodeEvidenceSubmission{
			ClusterId:           "prod-eu1",
			NodeName:            testNodeName,
			NodeUid:             fixtureNodeUID,
			ProviderId:          nodeevidence.ProviderTPM2Quote,
			Format:              tpmlocal.EvidenceFormat,
			Payload:             payload,
			ChallengeId:         challenge.GetChallengeId(),
			RequestedTtlSeconds: 60,
		},
	})
	if err != nil {
		t.Fatalf("cross-certificate PublishNodeEvidence returned error: %v", err)
	}
	if stolen.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY ||
		stolen.GetDecision().GetErrors()[0].GetCode() != protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED {
		t.Fatalf("cross-certificate decision = %#v, want permission denied", stolen.GetDecision())
	}
}

func TestAdminServiceRejectsTPMChallengeForWrongNodeUID(t *testing.T) {
	t.Parallel()
	_, public := syntheticNodeEvidenceAK(t)
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 NewMemoryNodeEvidenceCache(),
		nodeEvidencePublishProviders: []string{nodeevidence.ProviderTPM2Quote},
		nodeEvidenceTPMPolicies: map[string]TPMNodeEvidencePolicy{
			testNodeName: {
				NodeUID: fixtureNodeUID,
				Policy: tpmlocal.Policy{
					Mode:                 tpmlocal.PolicyModeTPMOnly,
					EnrolledAKPublicHash: tpmlocal.PublicDigest(public),
				},
			},
		},
	})
	response, err := service.ChallengeNodeEvidence(context.Background(), &protocolv1.NodeEvidenceChallengeRequest{
		ClusterId:  "prod-eu1",
		NodeName:   testNodeName,
		NodeUid:    "wrong-node-uid",
		ProviderId: nodeevidence.ProviderTPM2Quote,
	})
	if err != nil {
		t.Fatalf("ChallengeNodeEvidence returned error: %v", err)
	}
	if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY {
		t.Fatalf("challenge decision = %s, want deny", response.GetDecision().GetState())
	}
	if response.GetChallengeId() != "" || len(response.GetNonce()) != 0 {
		t.Fatalf("denied challenge leaked challenge material: %#v", response)
	}
}

func TestAdminServiceRequiresNodeScopedTPMPublisherCertificate(t *testing.T) {
	t.Parallel()
	_, public := syntheticNodeEvidenceAK(t)
	authorizedCtx := nodeEvidencePublisherTestContext(t, []byte("authorized-publisher-certificate"))
	authorizedHash, err := nodeEvidenceClientCertificateHash(authorizedCtx)
	if err != nil {
		t.Fatalf("nodeEvidenceClientCertificateHash returned error: %v", err)
	}
	service := newAdminService(adminServiceConfig{
		nodeEvidence:                 NewMemoryNodeEvidenceCache(),
		nodeEvidencePublishProviders: []string{nodeevidence.ProviderTPM2Quote},
		nodeEvidenceTPMPolicies: map[string]TPMNodeEvidencePolicy{
			testNodeName: {
				NodeUID: fixtureNodeUID,
				Policy: tpmlocal.Policy{
					Mode:                 tpmlocal.PolicyModeTPMOnly,
					EnrolledAKPublicHash: tpmlocal.PublicDigest(public),
				},
			},
		},
		nodeEvidencePublishers: map[string]NodeEvidencePublisher{
			authorizedHash: {NodeNames: []string{testNodeName}},
		},
	})
	request := &protocolv1.NodeEvidenceChallengeRequest{
		ClusterId:  "prod-eu1",
		NodeName:   testNodeName,
		NodeUid:    fixtureNodeUID,
		ProviderId: nodeevidence.ProviderTPM2Quote,
	}
	tests := []struct {
		name     string
		ctx      context.Context
		wantCode protocolv1.ErrorCode
	}{
		{
			name:     "missing client certificate",
			ctx:      context.Background(),
			wantCode: protocolv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED,
		},
		{
			name:     "unlisted client certificate",
			ctx:      nodeEvidencePublisherTestContext(t, []byte("unlisted-publisher-certificate")),
			wantCode: protocolv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := service.ChallengeNodeEvidence(test.ctx, request)
			if err != nil {
				t.Fatalf("ChallengeNodeEvidence returned error: %v", err)
			}
			if response.GetDecision().GetState() != protocolv1.PolicyDecisionState_POLICY_DECISION_STATE_DENY ||
				response.GetDecision().GetErrors()[0].GetCode() != test.wantCode {
				t.Fatalf("challenge decision = %#v, want deny/%s", response.GetDecision(), test.wantCode)
			}
			if response.GetChallengeId() != "" || len(response.GetNonce()) != 0 {
				t.Fatalf("denied challenge leaked challenge material: %#v", response)
			}
		})
	}
}

func nodeEvidencePublisherTestContext(t *testing.T, certificateDER []byte) context.Context {
	t.Helper()
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Raw: certificateDER}},
		}},
	})
}

func syntheticNodeEvidenceAK(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	public, err := (legacytpm2.Public{
		Type:       legacytpm2.AlgRSA,
		NameAlg:    legacytpm2.AlgSHA256,
		Attributes: legacytpm2.FlagSignerDefault,
		RSAParameters: &legacytpm2.RSAParams{
			Sign:       &legacytpm2.SigScheme{Alg: legacytpm2.AlgRSASSA, Hash: legacytpm2.AlgSHA256},
			KeyBits:    2048,
			ModulusRaw: key.PublicKey.N.Bytes(),
		},
	}).Encode()
	if err != nil {
		t.Fatalf("Encode public returned error: %v", err)
	}
	return key, public
}

func syntheticNodeTPMEvidence(
	t *testing.T,
	key *rsa.PrivateKey,
	public []byte,
	challengeID string,
	nonce []byte,
) tpmlocal.Evidence {
	t.Helper()
	selection := tpmlocal.PCRSelection{Hash: tpmlocal.HashSHA256, PCRs: []int{7}}
	pcrValues := map[int][]byte{7: bytes.Repeat([]byte{0x07}, sha256.Size)}
	pcrDigest, err := tpmlocal.ComputePCRDigest(selection, pcrValues)
	if err != nil {
		t.Fatalf("ComputePCRDigest returned error: %v", err)
	}
	quote, err := (legacytpm2.AttestationData{
		Magic:           0xff544347,
		Type:            legacytpm2.TagAttestQuote,
		ExtraData:       nonce,
		ClockInfo:       legacytpm2.ClockInfo{Safe: 1},
		FirmwareVersion: 1,
		AttestedQuoteInfo: &legacytpm2.QuoteInfo{
			PCRSelection: legacytpm2.PCRSelection{Hash: legacytpm2.AlgSHA256, PCRs: []int{7}},
			PCRDigest:    pcrDigest,
		},
	}).Encode()
	if err != nil {
		t.Fatalf("Encode attestation returned error: %v", err)
	}
	digest := sha256.Sum256(quote)
	rawSignature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15 returned error: %v", err)
	}
	signature, err := (legacytpm2.Signature{
		Alg: legacytpm2.AlgRSASSA,
		RSA: &legacytpm2.SignatureRSA{
			HashAlg:   legacytpm2.AlgSHA256,
			Signature: rawSignature,
		},
	}).Encode()
	if err != nil {
		t.Fatalf("Encode signature returned error: %v", err)
	}
	return tpmlocal.Evidence{
		SchemaVersion: tpmlocal.EvidenceSchemaVersion,
		ChallengeID:   challengeID,
		NonceHash:     tpmlocal.NonceDigest(nonce),
		AKPublic:      public,
		Quote:         quote,
		Signature:     signature,
		PCRSelection:  selection,
		PCRValues:     tpmlocal.EncodePCRValues(pcrValues),
	}
}
