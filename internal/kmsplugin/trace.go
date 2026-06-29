package kmsplugin

import wrapping "github.com/openbao/go-kms-wrapping/v2"

type wrapperTraceEvent struct {
	Operation       string `json:"operation"`
	Mode            string `json:"mode"`
	KeyID           string `json:"key_id"`
	PlaintextBytes  int    `json:"plaintext_bytes"`
	CiphertextBytes int    `json:"ciphertext_bytes"`
	AADBytes        int    `json:"aad_bytes"`
}

func blobTraceKeyID(blob *wrapping.BlobInfo) string {
	keyInfo := blob.GetKeyInfo()
	if keyInfo == nil {
		return ""
	}
	return keyInfo.GetKeyId()
}
