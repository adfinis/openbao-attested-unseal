package broker

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
	"google.golang.org/protobuf/proto"
)

func randomID(prefix string) (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate %s ID: %w", prefix, err)
	}
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(random), nil
}

func randomNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate challenge nonce: %w", err)
	}
	return nonce, nil
}

func evidenceHash(evidence *protocolv1.EvidenceEnvelope) string {
	if evidence == nil {
		return ""
	}
	encoded, err := proto.Marshal(evidence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
