package nodeagent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

func TestTPMProviderCollectsRawQuoteForBrokerChallenge(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x42}, 32)
	challenge := nodeevidence.Challenge{ID: "node_chal_test", Nonce: nonce, ExpiresAt: time.Now().Add(time.Minute)}
	collector := &staticTPMQuoteCollector{
		collect: func(
			challengeID string,
			quoteNonce []byte,
			selection tpmlocal.PCRSelection,
			platformHint string,
		) (tpmlocal.Evidence, error) {
			return syntheticTPMNodeEvidence(t, challengeID, quoteNonce, selection, platformHint), nil
		},
	}
	provider := TPMProvider{
		Selection:    tpmlocal.PCRSelection{Hash: "SHA256", PCRs: []int{7}},
		PlatformHint: tpmlocal.ProfileGenericPCSecureBoot,
		Collector:    collector,
	}

	out, err := provider.CollectNodeEvidence(context.Background(), PublishRequest{
		ClusterID: "prod-eu1",
		NodeName:  "node-a",
		NodeUID:   "node-uid-a",
		TTL:       time.Minute,
	}, challenge)
	if err != nil {
		t.Fatalf("CollectNodeEvidence returned error: %v", err)
	}
	if provider.ProviderID() != nodeevidence.ProviderTPM2Quote {
		t.Fatalf("provider_id = %q, want %s", provider.ProviderID(), nodeevidence.ProviderTPM2Quote)
	}
	if out.Format != tpmlocal.EvidenceFormat || len(out.Payload) == 0 {
		t.Fatalf("provider evidence = %#v, want raw TPM payload", out)
	}
	if collector.challengeID != challenge.ID {
		t.Fatalf("challenge ID = %q, want %q", collector.challengeID, challenge.ID)
	}
	if !bytes.Equal(collector.nonce, nonce) {
		t.Fatalf("nonce = %x, want %x", collector.nonce, nonce)
	}
	if collector.selection.Hash != tpmlocal.HashSHA256 || !slices.Equal(collector.selection.PCRs, []int{7}) {
		t.Fatalf("selection = %#v, want sha256 PCR 7", collector.selection)
	}
	if collector.platformHint != tpmlocal.ProfileGenericPCSecureBoot {
		t.Fatalf("platform hint = %q, want secureboot profile", collector.platformHint)
	}
}

func TestTPMProviderDefaultsToPCR7(t *testing.T) {
	collector := &staticTPMQuoteCollector{
		collect: func(
			challengeID string,
			quoteNonce []byte,
			selection tpmlocal.PCRSelection,
			platformHint string,
		) (tpmlocal.Evidence, error) {
			return syntheticTPMNodeEvidence(t, challengeID, quoteNonce, selection, platformHint), nil
		},
	}
	provider := TPMProvider{
		Collector: collector,
	}
	challenge := nodeevidence.Challenge{
		ID:        "node_chal_default",
		Nonce:     bytes.Repeat([]byte{0x24}, 32),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	_, err := provider.CollectNodeEvidence(context.Background(), PublishRequest{
		ClusterID: "prod-eu1",
		NodeName:  "node-a",
		TTL:       time.Minute,
	}, challenge)
	if err != nil {
		t.Fatalf("CollectNodeEvidence returned error: %v", err)
	}
	if collector.selection.Hash != tpmlocal.HashSHA256 || !slices.Equal(collector.selection.PCRs, []int{7}) {
		t.Fatalf("default selection = %#v, want sha256 PCR 7", collector.selection)
	}
}

func TestTPMProviderRejectsQuoteNonceMismatch(t *testing.T) {
	wrongNonce := bytes.Repeat([]byte{0x13}, 32)
	collector := &staticTPMQuoteCollector{
		collect: func(
			challengeID string,
			_ []byte,
			selection tpmlocal.PCRSelection,
			platformHint string,
		) (tpmlocal.Evidence, error) {
			return syntheticTPMNodeEvidence(t, challengeID, wrongNonce, selection, platformHint), nil
		},
	}
	provider := TPMProvider{
		Collector: collector,
	}
	challenge := nodeevidence.Challenge{
		ID:        "node_chal_mismatch",
		Nonce:     bytes.Repeat([]byte{0x42}, 32),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	_, err := provider.CollectNodeEvidence(context.Background(), PublishRequest{
		ClusterID: "prod-eu1",
		NodeName:  "node-a",
		TTL:       time.Minute,
	}, challenge)
	if !errors.Is(err, ErrTPMNodeEvidence) || !errors.Is(err, tpmlocal.ErrQuoteVerification) {
		t.Fatalf("CollectNodeEvidence error = %v, want TPM quote verification failure", err)
	}
}

func TestTPMProviderReturnsCollectorError(t *testing.T) {
	collectorErr := errors.New("collector failed")
	provider := TPMProvider{
		Collector: &staticTPMQuoteCollector{err: collectorErr},
	}
	challenge := nodeevidence.Challenge{
		ID:        "node_chal_error",
		Nonce:     bytes.Repeat([]byte{0x42}, 32),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	_, err := provider.CollectNodeEvidence(context.Background(), PublishRequest{
		ClusterID: "prod-eu1",
		NodeName:  "node-a",
		TTL:       time.Minute,
	}, challenge)
	if !errors.Is(err, ErrTPMNodeEvidence) || !errors.Is(err, collectorErr) {
		t.Fatalf("CollectNodeEvidence error = %v, want collector failure", err)
	}
}

type staticTPMQuoteCollector struct {
	collect      func(string, []byte, tpmlocal.PCRSelection, string) (tpmlocal.Evidence, error)
	err          error
	challengeID  string
	nonce        []byte
	selection    tpmlocal.PCRSelection
	platformHint string
}

func (c *staticTPMQuoteCollector) CollectTPMQuote(
	_ context.Context,
	challengeID string,
	nonce []byte,
	selection tpmlocal.PCRSelection,
	platformHint string,
) (tpmlocal.Evidence, error) {
	c.challengeID = challengeID
	c.nonce = slices.Clone(nonce)
	c.selection = selection
	c.platformHint = platformHint
	if c.err != nil {
		return tpmlocal.Evidence{}, c.err
	}
	return c.collect(challengeID, nonce, selection, platformHint)
}

func syntheticTPMNodeEvidence(
	t *testing.T,
	challengeID string,
	nonce []byte,
	selection tpmlocal.PCRSelection,
	platformHint string,
) tpmlocal.Evidence {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	normalized, err := selection.Normalize()
	if err != nil {
		t.Fatalf("Normalize returned error: %v", err)
	}
	values := make(map[int][]byte, len(normalized.PCRs))
	for _, pcr := range normalized.PCRs {
		values[pcr] = bytes.Repeat([]byte{0x07}, sha256.Size)
	}
	pcrDigest, err := tpmlocal.ComputePCRDigest(normalized, values)
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
			PCRSelection: legacytpm2.PCRSelection{
				Hash: legacytpm2.AlgSHA256,
				PCRs: normalized.PCRs,
			},
			PCRDigest: pcrDigest,
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
	evidence := tpmlocal.Evidence{
		SchemaVersion: tpmlocal.EvidenceSchemaVersion,
		ChallengeID:   challengeID,
		NonceHash:     tpmlocal.NonceDigest(nonce),
		AKPublic:      encodeTPMRSAKey(t, &key.PublicKey),
		Quote:         quote,
		Signature:     signature,
		PCRSelection:  normalized,
		PCRValues:     tpmlocal.EncodePCRValues(values),
		PlatformHint:  platformHint,
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	return evidence
}

func encodeTPMRSAKey(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	public, err := (legacytpm2.Public{
		Type:       legacytpm2.AlgRSA,
		NameAlg:    legacytpm2.AlgSHA256,
		Attributes: legacytpm2.FlagSignerDefault,
		RSAParameters: &legacytpm2.RSAParams{
			Sign: &legacytpm2.SigScheme{
				Alg:  legacytpm2.AlgRSASSA,
				Hash: legacytpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: key.N.Bytes(),
		},
	}).Encode()
	if err != nil {
		t.Fatalf("Encode public returned error: %v", err)
	}
	return public
}
