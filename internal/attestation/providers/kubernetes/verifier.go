package kubernetes

import (
	"context"
	"fmt"
	"slices"
	"strings"

	protocolv1 "github.com/adfinis/openbao-attested-unseal/internal/protocol/v1"
)

const (
	extraPodName  = "authentication.kubernetes.io/pod-name"
	extraPodUID   = "authentication.kubernetes.io/pod-uid"
	extraNodeName = "authentication.kubernetes.io/node-name"
	extraNodeUID  = "authentication.kubernetes.io/node-uid"
)

// ErrUnauthenticated indicates a token was reviewed but not authenticated.
var ErrUnauthenticated = fmt.Errorf("%w: token is not authenticated", ErrInvalidEvidence)

// VerifierConfig constrains accepted Kubernetes workload identity.
type VerifierConfig struct {
	Audience          string
	Namespace         string
	ServiceAccount    string
	RequirePodBinding bool
}

// Claims are normalized Kubernetes workload identity facts.
type Claims struct {
	Subject        string
	Namespace      string
	ServiceAccount string
	Username       string
	UID            string
	Groups         []string
	Audiences      []string
	PodName        string
	PodUID         string
	NodeName       string
	NodeUID        string
}

// Verifier validates Kubernetes workload evidence through TokenReview.
type Verifier struct {
	Reviewer TokenReviewer
	Config   VerifierConfig
}

// Verify validates a Kubernetes evidence envelope and returns normalized claims.
func (v Verifier) Verify(
	ctx context.Context,
	envelope *protocolv1.EvidenceEnvelope,
) (*protocolv1.EvidenceEnvelope, Claims, error) {
	payload, err := decodeEvidencePayload(envelope)
	if err != nil {
		return nil, Claims{}, err
	}
	if v.Reviewer == nil {
		return nil, Claims{}, fmt.Errorf("%w: token reviewer is required", ErrTokenReview)
	}
	status, err := v.reviewToken(ctx, payload.Token)
	if err != nil {
		return nil, Claims{}, err
	}
	claims, err := v.claimsFromStatus(status)
	if err != nil {
		return nil, Claims{}, err
	}
	out := &protocolv1.EvidenceEnvelope{
		Provider:         envelope.GetProvider(),
		Format:           envelope.GetFormat(),
		Payload:          envelope.GetPayload(),
		ChallengeId:      envelope.GetChallengeId(),
		NormalizedClaims: ClaimsToProto(claims),
	}
	return out, claims, nil
}

func (v Verifier) reviewToken(ctx context.Context, token string) (TokenReviewStatus, error) {
	audiences := []string(nil)
	if strings.TrimSpace(v.Config.Audience) != "" {
		audiences = []string{strings.TrimSpace(v.Config.Audience)}
	}
	return v.Reviewer.ReviewToken(ctx, TokenReviewRequest{
		Token:     token,
		Audiences: audiences,
	})
}

func (v Verifier) claimsFromStatus(status TokenReviewStatus) (Claims, error) {
	if !status.Authenticated || status.Error != "" {
		return Claims{}, ErrUnauthenticated
	}
	if expected := strings.TrimSpace(v.Config.Audience); expected != "" &&
		!slices.Contains(status.Audiences, expected) {
		return Claims{}, fmt.Errorf("%w: audience was not accepted", ErrInvalidEvidence)
	}
	namespace, serviceAccount, err := parseServiceAccountUsername(status.User.Username)
	if err != nil {
		return Claims{}, err
	}
	if err := v.validateServiceAccount(namespace, serviceAccount); err != nil {
		return Claims{}, err
	}
	claims := Claims{
		Subject:        namespace + "." + serviceAccount,
		Namespace:      namespace,
		ServiceAccount: serviceAccount,
		Username:       status.User.Username,
		UID:            status.User.UID,
		Groups:         append([]string(nil), status.User.Groups...),
		Audiences:      append([]string(nil), status.Audiences...),
		PodName:        firstExtra(status.User.Extra, extraPodName),
		PodUID:         firstExtra(status.User.Extra, extraPodUID),
		NodeName:       firstExtra(status.User.Extra, extraNodeName),
		NodeUID:        firstExtra(status.User.Extra, extraNodeUID),
	}
	if v.Config.RequirePodBinding && (claims.PodUID == "" || claims.NodeName == "") {
		return Claims{}, fmt.Errorf("%w: pod-bound token claims are required", ErrInvalidEvidence)
	}
	return claims, nil
}

func (v Verifier) validateServiceAccount(namespace string, serviceAccount string) error {
	if expected := strings.TrimSpace(v.Config.Namespace); expected != "" && namespace != expected {
		return fmt.Errorf("%w: namespace is not allowed", ErrInvalidEvidence)
	}
	if expected := strings.TrimSpace(v.Config.ServiceAccount); expected != "" && serviceAccount != expected {
		return fmt.Errorf("%w: service account is not allowed", ErrInvalidEvidence)
	}
	return nil
}

// ClaimsToProto maps verified Kubernetes workload facts into normalized claims.
func ClaimsToProto(claims Claims) []*protocolv1.Claim {
	out := []*protocolv1.Claim{
		{Namespace: "dev", Name: "subject", Value: claims.Subject},
		{Namespace: ClaimNamespace, Name: "namespace", Value: claims.Namespace},
		{Namespace: ClaimNamespace, Name: "service_account", Value: claims.ServiceAccount},
		{Namespace: ClaimNamespace, Name: "username", Value: claims.Username},
	}
	add := func(name string, value string) {
		if value == "" {
			return
		}
		out = append(out, &protocolv1.Claim{Namespace: ClaimNamespace, Name: name, Value: value})
	}
	add("uid", claims.UID)
	add("audiences", strings.Join(claims.Audiences, ","))
	add("pod_name", claims.PodName)
	add("pod_uid", claims.PodUID)
	add("node_name", claims.NodeName)
	add("node_uid", claims.NodeUID)
	return out
}

func parseServiceAccountUsername(username string) (string, string, error) {
	parts := strings.Split(username, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
		return "", "", fmt.Errorf("%w: username is not a service account", ErrInvalidEvidence)
	}
	if parts[2] == "" || parts[3] == "" {
		return "", "", fmt.Errorf("%w: service account username is incomplete", ErrInvalidEvidence)
	}
	return parts[2], parts[3], nil
}

func firstExtra(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
