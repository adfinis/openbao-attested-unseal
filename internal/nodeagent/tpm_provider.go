package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"strings"

	tpmprovider "github.com/adfinis/openbao-attested-unseal/internal/attestation/providers/tpm"
	"github.com/adfinis/openbao-attested-unseal/internal/nodeevidence"
	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

var (
	// ErrTPMNodeEvidence indicates that TPM node evidence collection or local verification failed.
	ErrTPMNodeEvidence = errors.New("TPM node evidence failed")
)

// TPMQuoteCollector collects one TPM quote for node evidence publishing.
type TPMQuoteCollector interface {
	CollectTPMQuote(
		context.Context,
		string,
		[]byte,
		tpmlocal.PCRSelection,
		string,
	) (tpmlocal.Evidence, error)
}

// TPMProvider publishes metadata derived from a locally verified generic TPM 2.0 quote.
type TPMProvider struct {
	Device       tpmlocal.Device
	Selection    tpmlocal.PCRSelection
	PlatformHint string
	Collector    TPMQuoteCollector
}

// ProviderID returns the broker TPM quote provider identifier.
func (TPMProvider) ProviderID() string {
	return nodeevidence.ProviderTPM2Quote
}

// CollectNodeEvidence collects a TPM quote for a broker challenge and verifies it as a local self-check.
func (p TPMProvider) CollectNodeEvidence(
	ctx context.Context,
	_ PublishRequest,
	challenge nodeevidence.Challenge,
) (ProviderEvidence, error) {
	if err := ctx.Err(); err != nil {
		return ProviderEvidence{}, err
	}
	selection, err := p.pcrSelection()
	if err != nil {
		return ProviderEvidence{}, fmt.Errorf("%w: %w", ErrTPMNodeEvidence, err)
	}
	challenge, err = nodeevidence.NormalizeChallenge(challenge)
	if err != nil {
		return ProviderEvidence{}, fmt.Errorf("%w: invalid broker challenge: %w", ErrTPMNodeEvidence, err)
	}
	evidence, err := p.quoteCollector().CollectTPMQuote(
		ctx,
		challenge.ID,
		challenge.Nonce,
		selection,
		strings.TrimSpace(p.PlatformHint),
	)
	if err != nil {
		return ProviderEvidence{}, fmt.Errorf("%w: collect quote: %w", ErrTPMNodeEvidence, err)
	}
	if _, err := tpmlocal.VerifyQuote(evidence, challenge.Nonce); err != nil {
		return ProviderEvidence{}, fmt.Errorf("%w: verify quote: %w", ErrTPMNodeEvidence, err)
	}
	payload, err := evidence.Marshal()
	if err != nil {
		return ProviderEvidence{}, fmt.Errorf("%w: marshal quote: %w", ErrTPMNodeEvidence, err)
	}
	return ProviderEvidence{
		Format:  tpmlocal.EvidenceFormat,
		Payload: payload,
	}, nil
}

func (p TPMProvider) pcrSelection() (tpmlocal.PCRSelection, error) {
	selection := p.Selection
	if selection.Hash == "" && len(selection.PCRs) == 0 {
		selection = tpmlocal.PCRSelection{Hash: tpmlocal.HashSHA256, PCRs: []int{7}}
	}
	return selection.Normalize()
}

func (p TPMProvider) quoteCollector() TPMQuoteCollector {
	if p.Collector != nil {
		return p.Collector
	}
	return localTPMQuoteCollector{Device: p.Device}
}

type localTPMQuoteCollector struct {
	Device tpmlocal.Device
}

func (c localTPMQuoteCollector) CollectTPMQuote(
	ctx context.Context,
	challengeID string,
	nonce []byte,
	selection tpmlocal.PCRSelection,
	platformHint string,
) (tpmlocal.Evidence, error) {
	envelope, err := (tpmprovider.Provider{Device: c.Device}).Collect(
		ctx,
		challengeID,
		nonce,
		selection,
		platformHint,
	)
	if err != nil {
		return tpmlocal.Evidence{}, err
	}
	return tpmlocal.UnmarshalEvidence(envelope.GetPayload())
}
