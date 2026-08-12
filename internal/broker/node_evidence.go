package broker

import "github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"

var (
	// ErrNodeEvidenceNotFound is retained while broker callers migrate to nodeevidence.
	ErrNodeEvidenceNotFound = nodeevidence.ErrNotFound
	// ErrNodeEvidenceStale is retained while broker callers migrate to nodeevidence.
	ErrNodeEvidenceStale = nodeevidence.ErrStale
	// ErrNodeEvidenceInvalid is retained while broker callers migrate to nodeevidence.
	ErrNodeEvidenceInvalid = nodeevidence.ErrInvalid
)

const (
	// NodeEvidenceProviderFakeLocal is retained while callers migrate to nodeevidence.
	NodeEvidenceProviderFakeLocal = nodeevidence.ProviderFakeLocal
	// NodeEvidenceProviderTPM2Quote is retained while callers migrate to nodeevidence.
	NodeEvidenceProviderTPM2Quote = nodeevidence.ProviderTPM2Quote
)

type (
	// NodeEvidence is retained while broker callers migrate to nodeevidence.Evidence.
	NodeEvidence = nodeevidence.Evidence
	// NodeEvidenceReader is retained while broker callers migrate to nodeevidence.Reader.
	NodeEvidenceReader = nodeevidence.Reader
	// NodeEvidenceWriter is retained while broker callers migrate to nodeevidence.Writer.
	NodeEvidenceWriter = nodeevidence.Writer
	// NodeEvidenceStore is retained while broker callers migrate to nodeevidence.Repository.
	NodeEvidenceStore = nodeevidence.Repository
	// MemoryNodeEvidenceCache is retained while tests migrate to nodeevidence.MemoryRepository.
	MemoryNodeEvidenceCache = nodeevidence.MemoryRepository
)

// NewMemoryNodeEvidenceCache is retained while tests migrate to nodeevidence.NewMemoryRepository.
var NewMemoryNodeEvidenceCache = nodeevidence.NewMemoryRepository

func normalizeNodeEvidence(evidence NodeEvidence) (NodeEvidence, error) {
	return nodeevidence.Normalize(evidence)
}
