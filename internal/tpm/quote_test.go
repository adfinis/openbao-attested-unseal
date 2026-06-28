package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"testing"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
)

func TestVerifyQuoteAcceptsBoundNonceAndAK(t *testing.T) {
	evidence, nonce := syntheticEvidence(t)
	claims, err := VerifyQuote(evidence, nonce)
	if err != nil {
		t.Fatalf("VerifyQuote returned error: %v", err)
	}
	if claims.AKPublicHash != PublicDigest(evidence.AKPublic) {
		t.Fatalf("AK hash = %q, want %q", claims.AKPublicHash, PublicDigest(evidence.AKPublic))
	}
	if !claims.PCRSelection.contains(7) {
		t.Fatalf("claims missing PCR 7: %#v", claims.PCRSelection)
	}
}

func TestVerifyQuoteRejectsWrongNonce(t *testing.T) {
	evidence, _ := syntheticEvidence(t)
	_, err := VerifyQuote(evidence, []byte("wrong nonce"))
	if !errors.Is(err, ErrQuoteVerification) {
		t.Fatalf("VerifyQuote error = %v, want ErrQuoteVerification", err)
	}
}

func TestVerifyQuoteRejectsWrongAK(t *testing.T) {
	evidence, nonce := syntheticEvidence(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	evidence.AKPublic = encodeRSAPublic(t, &otherKey.PublicKey)
	_, err = VerifyQuote(evidence, nonce)
	if !errors.Is(err, ErrQuoteVerification) {
		t.Fatalf("VerifyQuote error = %v, want ErrQuoteVerification", err)
	}
}

func TestEvaluatePolicySecureBootRejectsPCRMismatch(t *testing.T) {
	evidence, nonce := syntheticEvidence(t)
	policy, err := NewPCRPolicy(
		PCRSelection{Hash: HashSHA256, PCRs: []int{7}},
		map[int][]byte{7: bytesOf(1, sha256.Size)},
		ProfileGenericPCSecureBoot,
	)
	if err != nil {
		t.Fatalf("NewPCRPolicy returned error: %v", err)
	}
	_, err = EvaluatePolicy(evidence, nonce, Policy{
		Mode:                 PolicyModeSecureBoot,
		EnrolledAKPublicHash: PublicDigest(evidence.AKPublic),
		PCRPolicy:            &policy,
		ProviderProfile:      ProfileGenericPCSecureBoot,
	})
	if !errors.Is(err, ErrAttestationPolicy) {
		t.Fatalf("EvaluatePolicy error = %v, want ErrAttestationPolicy", err)
	}
}

func TestEvaluatePolicySecureBootAcceptsPCR7Policy(t *testing.T) {
	evidence, nonce := syntheticEvidence(t)
	values, err := DecodePCRValues(evidence.PCRValues)
	if err != nil {
		t.Fatalf("DecodePCRValues returned error: %v", err)
	}
	policy, err := NewPCRPolicy(evidence.PCRSelection, values, ProfileGenericPCSecureBoot)
	if err != nil {
		t.Fatalf("NewPCRPolicy returned error: %v", err)
	}
	claims, err := EvaluatePolicy(evidence, nonce, Policy{
		Mode:                 PolicyModeSecureBoot,
		EnrolledAKPublicHash: PublicDigest(evidence.AKPublic),
		PCRPolicy:            &policy,
		ProviderProfile:      ProfileGenericPCSecureBoot,
	})
	if err != nil {
		t.Fatalf("EvaluatePolicy returned error: %v", err)
	}
	if !claims.SecureBoot {
		t.Fatal("SecureBoot claim is false")
	}
}

func syntheticEvidence(t *testing.T) (Evidence, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}
	nonce := []byte("broker nonce")
	selection := PCRSelection{Hash: HashSHA256, PCRs: []int{7}}
	values := map[int][]byte{7: bytesOf(7, sha256.Size)}
	pcrDigest, err := ComputePCRDigest(selection, values)
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
	evidence := Evidence{
		SchemaVersion: EvidenceSchemaVersion,
		ChallengeID:   "chal_test",
		NonceHash:     NonceDigest(nonce),
		AKPublic:      encodeRSAPublic(t, &key.PublicKey),
		Quote:         quote,
		Signature:     signature,
		PCRSelection:  selection,
		PCRValues:     EncodePCRValues(values),
		PlatformHint:  ProfileGenericPCSecureBoot,
	}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	return evidence, nonce
}

func encodeRSAPublic(t *testing.T, key *rsa.PublicKey) []byte {
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

func bytesOf(value byte, size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = value
	}
	return out
}
