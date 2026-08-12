package nodeevidence

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	tpmlocal "github.com/adfinis/openbao-attested-unseal/internal/tpm"
)

var (
	// ErrEnrollmentNotFound indicates that no node trust enrollment exists.
	ErrEnrollmentNotFound = errors.New("node evidence enrollment not found")
	// ErrEnrollmentRevoked indicates that a node trust enrollment is revoked.
	ErrEnrollmentRevoked = errors.New("node evidence enrollment revoked")
	// ErrEnrollmentChanged indicates that trust changed before verified evidence was stored.
	ErrEnrollmentChanged = errors.New("node evidence enrollment changed")
	// ErrInvalidEnrollment indicates malformed node trust enrollment input.
	ErrInvalidEnrollment = errors.New("invalid node evidence enrollment")
)

// EnrollmentRequest is the operator-approved trust policy for one node.
type EnrollmentRequest struct {
	ClusterID                  string
	NodeName                   string
	NodeUID                    string
	Provider                   string
	TPMPolicy                  tpmlocal.Policy
	PublisherCertificateHashes []string
	EnrolledAt                 time.Time
}

// Enrollment is the durable, revisioned trust policy used to verify node evidence.
type Enrollment struct {
	ClusterID                  string
	NodeName                   string
	NodeUID                    string
	Provider                   string
	TPMPolicy                  tpmlocal.Policy
	PublisherCertificateHashes []string
	Revision                   uint64
	EnrolledAt                 time.Time
	UpdatedAt                  time.Time
	RevokedAt                  time.Time
}

// Active reports whether the enrollment may authorize evidence publication.
func (e Enrollment) Active() bool {
	return e.RevokedAt.IsZero()
}

// EnrollmentRepository owns the lifecycle of node trust policies.
//
// Enroll and Revoke must invalidate previously verified evidence for the node.
// PutEnrolledNodeEvidence must reject records whose enrollment revision is no
// longer active, closing the race between verification and a trust change.
type EnrollmentRepository interface {
	EnrollNodeEvidence(context.Context, EnrollmentRequest) (Enrollment, error)
	RevokeNodeEvidence(context.Context, string, string, time.Time) (Enrollment, error)
	ActiveNodeEvidenceEnrollment(context.Context, string, string) (Enrollment, error)
	ListNodeEvidenceEnrollments(context.Context, string, string, bool) ([]Enrollment, error)
	PutEnrolledNodeEvidence(context.Context, Evidence, uint64) error
}

// NormalizeEnrollmentRequest validates and clones operator-supplied node trust.
func NormalizeEnrollmentRequest(request EnrollmentRequest) (EnrollmentRequest, error) {
	request.ClusterID = strings.TrimSpace(request.ClusterID)
	request.NodeName = strings.TrimSpace(request.NodeName)
	request.NodeUID = strings.TrimSpace(request.NodeUID)
	request.Provider = strings.TrimSpace(request.Provider)
	request.TPMPolicy = cloneTPMPolicy(request.TPMPolicy)
	request.PublisherCertificateHashes = slices.Clone(request.PublisherCertificateHashes)
	if request.ClusterID == "" || request.NodeName == "" || request.NodeUID == "" {
		return EnrollmentRequest{}, fmt.Errorf(
			"%w: cluster_id, node_name, and node_uid are required",
			ErrInvalidEnrollment,
		)
	}
	if request.Provider != ProviderTPM2Quote {
		return EnrollmentRequest{}, fmt.Errorf(
			"%w: unsupported provider %q",
			ErrInvalidEnrollment,
			request.Provider,
		)
	}
	if strings.TrimSpace(request.TPMPolicy.EnrolledAKPublicHash) == "" {
		return EnrollmentRequest{}, fmt.Errorf(
			"%w: enrolled AK public hash is required",
			ErrInvalidEnrollment,
		)
	}
	if err := request.TPMPolicy.Validate(); err != nil {
		return EnrollmentRequest{}, fmt.Errorf("%w: %v", ErrInvalidEnrollment, err)
	}
	if len(request.PublisherCertificateHashes) == 0 {
		return EnrollmentRequest{}, fmt.Errorf(
			"%w: at least one publisher certificate hash is required",
			ErrInvalidEnrollment,
		)
	}
	seen := make(map[string]struct{}, len(request.PublisherCertificateHashes))
	for i, value := range request.PublisherCertificateHashes {
		canonical, err := CanonicalSHA256Digest(value)
		if err != nil {
			return EnrollmentRequest{}, fmt.Errorf(
				"%w: invalid publisher certificate hash: %v",
				ErrInvalidEnrollment,
				err,
			)
		}
		if _, ok := seen[canonical]; ok {
			return EnrollmentRequest{}, fmt.Errorf(
				"%w: duplicate publisher certificate hash",
				ErrInvalidEnrollment,
			)
		}
		seen[canonical] = struct{}{}
		request.PublisherCertificateHashes[i] = canonical
	}
	slices.Sort(request.PublisherCertificateHashes)
	if request.EnrolledAt.IsZero() {
		return EnrollmentRequest{}, fmt.Errorf("%w: enrolled_at is required", ErrInvalidEnrollment)
	}
	request.EnrolledAt = request.EnrolledAt.UTC()
	return request, nil
}

// NormalizeEnrollment validates and clones a durable enrollment record.
func NormalizeEnrollment(enrollment Enrollment) (Enrollment, error) {
	request, err := NormalizeEnrollmentRequest(EnrollmentRequest{
		ClusterID:                  enrollment.ClusterID,
		NodeName:                   enrollment.NodeName,
		NodeUID:                    enrollment.NodeUID,
		Provider:                   enrollment.Provider,
		TPMPolicy:                  enrollment.TPMPolicy,
		PublisherCertificateHashes: enrollment.PublisherCertificateHashes,
		EnrolledAt:                 enrollment.EnrolledAt,
	})
	if err != nil {
		return Enrollment{}, err
	}
	if enrollment.Revision == 0 || enrollment.UpdatedAt.IsZero() {
		return Enrollment{}, fmt.Errorf(
			"%w: revision and updated_at are required",
			ErrInvalidEnrollment,
		)
	}
	if enrollment.UpdatedAt.Before(request.EnrolledAt) {
		return Enrollment{}, fmt.Errorf(
			"%w: updated_at precedes enrolled_at",
			ErrInvalidEnrollment,
		)
	}
	if !enrollment.RevokedAt.IsZero() && enrollment.RevokedAt.Before(enrollment.UpdatedAt) {
		return Enrollment{}, fmt.Errorf(
			"%w: revoked_at precedes updated_at",
			ErrInvalidEnrollment,
		)
	}
	return Enrollment{
		ClusterID:                  request.ClusterID,
		NodeName:                   request.NodeName,
		NodeUID:                    request.NodeUID,
		Provider:                   request.Provider,
		TPMPolicy:                  request.TPMPolicy,
		PublisherCertificateHashes: request.PublisherCertificateHashes,
		Revision:                   enrollment.Revision,
		EnrolledAt:                 request.EnrolledAt,
		UpdatedAt:                  enrollment.UpdatedAt.UTC(),
		RevokedAt:                  enrollment.RevokedAt.UTC(),
	}, nil
}

// AuthorizesPublisher reports whether the enrollment grants one certificate access.
func (e Enrollment) AuthorizesPublisher(certificateHash string) bool {
	canonical, err := CanonicalSHA256Digest(certificateHash)
	if err != nil {
		return false
	}
	for _, allowed := range e.PublisherCertificateHashes {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(canonical)) == 1 {
			return true
		}
	}
	return false
}

// CanonicalSHA256Digest validates a lowercase sha256:hex digest.
func CanonicalSHA256Digest(value string) (string, error) {
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
		return "", errors.New("SHA-256 digest is not canonical")
	}
	return canonical, nil
}

func cloneTPMPolicy(policy tpmlocal.Policy) tpmlocal.Policy {
	if policy.PCRPolicy == nil {
		return policy
	}
	pcrPolicy := *policy.PCRPolicy
	pcrPolicy.Selection.PCRs = slices.Clone(pcrPolicy.Selection.PCRs)
	if pcrPolicy.CapturedValues != nil {
		pcrPolicy.CapturedValues = make(map[string]string, len(pcrPolicy.CapturedValues))
		for key, value := range policy.PCRPolicy.CapturedValues {
			pcrPolicy.CapturedValues[key] = value
		}
	}
	policy.PCRPolicy = &pcrPolicy
	return policy
}

// MemoryEnrollmentRepository provides process-local lifecycle semantics for tests.
type MemoryEnrollmentRepository struct {
	mu          sync.RWMutex
	enrollments map[evidenceKey]Enrollment
	evidence    *MemoryRepository
}

// NewMemoryEnrollmentRepository creates an empty node trust repository.
func NewMemoryEnrollmentRepository(evidence *MemoryRepository) *MemoryEnrollmentRepository {
	return &MemoryEnrollmentRepository{
		enrollments: make(map[evidenceKey]Enrollment),
		evidence:    evidence,
	}
}

// EnrollNodeEvidence creates or replaces one active enrollment and increments its revision.
func (r *MemoryEnrollmentRepository) EnrollNodeEvidence(
	_ context.Context,
	request EnrollmentRequest,
) (Enrollment, error) {
	request, err := NormalizeEnrollmentRequest(request)
	if err != nil {
		return Enrollment{}, err
	}
	key := evidenceKey{clusterID: request.ClusterID, nodeName: request.NodeName}
	r.mu.Lock()
	defer r.mu.Unlock()
	revision := uint64(1)
	if current, ok := r.enrollments[key]; ok {
		revision = current.Revision + 1
	}
	enrollment := Enrollment{
		ClusterID:                  request.ClusterID,
		NodeName:                   request.NodeName,
		NodeUID:                    request.NodeUID,
		Provider:                   request.Provider,
		TPMPolicy:                  request.TPMPolicy,
		PublisherCertificateHashes: request.PublisherCertificateHashes,
		Revision:                   revision,
		EnrolledAt:                 request.EnrolledAt,
		UpdatedAt:                  request.EnrolledAt,
	}
	r.enrollments[key] = enrollment
	r.deleteEvidenceLocked(key)
	return enrollment, nil
}

// RevokeNodeEvidence revokes one enrollment and invalidates stored evidence.
func (r *MemoryEnrollmentRepository) RevokeNodeEvidence(
	_ context.Context,
	clusterID string,
	nodeName string,
	now time.Time,
) (Enrollment, error) {
	if now.IsZero() {
		return Enrollment{}, fmt.Errorf("%w: revocation time is required", ErrInvalidEnrollment)
	}
	key := evidenceKey{clusterID: strings.TrimSpace(clusterID), nodeName: strings.TrimSpace(nodeName)}
	r.mu.Lock()
	defer r.mu.Unlock()
	enrollment, ok := r.enrollments[key]
	if !ok {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if !enrollment.Active() {
		return enrollment, ErrEnrollmentRevoked
	}
	enrollment.Revision++
	enrollment.UpdatedAt = now.UTC()
	enrollment.RevokedAt = now.UTC()
	r.enrollments[key] = enrollment
	r.deleteEvidenceLocked(key)
	return enrollment, nil
}

// ActiveNodeEvidenceEnrollment returns active trust for one node.
func (r *MemoryEnrollmentRepository) ActiveNodeEvidenceEnrollment(
	_ context.Context,
	clusterID string,
	nodeName string,
) (Enrollment, error) {
	key := evidenceKey{clusterID: strings.TrimSpace(clusterID), nodeName: strings.TrimSpace(nodeName)}
	r.mu.RLock()
	defer r.mu.RUnlock()
	enrollment, ok := r.enrollments[key]
	if !ok {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if !enrollment.Active() {
		return enrollment, ErrEnrollmentRevoked
	}
	return NormalizeEnrollment(enrollment)
}

// ListNodeEvidenceEnrollments returns enrollment records for one cluster.
func (r *MemoryEnrollmentRepository) ListNodeEvidenceEnrollments(
	_ context.Context,
	clusterID string,
	nodeName string,
	includeRevoked bool,
) ([]Enrollment, error) {
	clusterID = strings.TrimSpace(clusterID)
	nodeName = strings.TrimSpace(nodeName)
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Enrollment, 0, len(r.enrollments))
	for key, enrollment := range r.enrollments {
		if key.clusterID != clusterID || (nodeName != "" && key.nodeName != nodeName) {
			continue
		}
		if !includeRevoked && !enrollment.Active() {
			continue
		}
		normalized, err := NormalizeEnrollment(enrollment)
		if err != nil {
			return nil, err
		}
		out = append(out, normalized)
	}
	if len(out) == 0 {
		return nil, ErrEnrollmentNotFound
	}
	slices.SortFunc(out, func(left, right Enrollment) int {
		return strings.Compare(left.NodeName, right.NodeName)
	})
	return out, nil
}

// PutEnrolledNodeEvidence stores evidence only for the currently active revision.
func (r *MemoryEnrollmentRepository) PutEnrolledNodeEvidence(
	ctx context.Context,
	evidence Evidence,
	revision uint64,
) error {
	key := evidenceKey{clusterID: evidence.ClusterID, nodeName: evidence.NodeName}
	r.mu.RLock()
	enrollment, ok := r.enrollments[key]
	if !ok || !enrollment.Active() || enrollment.Revision != revision {
		r.mu.RUnlock()
		return ErrEnrollmentChanged
	}
	if r.evidence == nil {
		r.mu.RUnlock()
		return fmt.Errorf("%w: evidence repository is nil", ErrInvalidEnrollment)
	}
	err := r.evidence.PutNodeEvidence(ctx, evidence)
	r.mu.RUnlock()
	return err
}

func (r *MemoryEnrollmentRepository) deleteEvidenceLocked(key evidenceKey) {
	if r.evidence == nil {
		return
	}
	r.evidence.mu.Lock()
	delete(r.evidence.records, key)
	r.evidence.mu.Unlock()
}
