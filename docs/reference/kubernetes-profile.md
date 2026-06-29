# Kubernetes Profile Examples

Status: draft

Last reviewed: 2026-06-29

These examples show the current Kubernetes runtime profile contract for
`bao-unseald`. They are intentionally beta examples, not production deployment
manifests.

The tracked Kubernetes manifests live under
[`deploy/kubernetes`](../../deploy/kubernetes/README.md). The RBAC manifest is
covered by the kind e2e test.

## Current Boundary

The broker can verify Kubernetes workload evidence when it receives an evidence
envelope with:

- provider `ATTESTATION_PROVIDER_KUBERNETES_WORKLOAD`;
- format `openbao-attested-unseal.kubernetes-workload.v1`;
- a projected service account token in the evidence payload.

The OpenBao KMS plugin emits this evidence when configured with
`evidence_mode = "kubernetes-workload"`. It reads the projected service account
token from `kubernetes_token_file`, or from the default in-cluster service
account token path when that field is omitted.

`node_id` is still required by the broker challenge path. For the current beta
profile it should match the normalized Kubernetes subject, such as
`openbao.openbao`.

## In-Cluster Broker Config

For an in-cluster broker, omit `api_server`, `ca_cert_file`, and
`bearer_token_file`. `bao-unseald` derives the API endpoint from the Kubernetes
service environment and uses the mounted service account token and CA file.

```json
{
  "listen_address": "0.0.0.0:8443",
  "tls_cert_file": "/etc/openbao-attested-unseal/tls.crt",
  "tls_key_file": "/etc/openbao-attested-unseal/tls.key",
  "client_ca_file": "/etc/openbao-attested-unseal/clients.crt",
  "require_client_cert": true,
  "sqlite_path": "/var/lib/openbao-attested-unseal/broker.db",
  "audit_file_path": "/var/log/openbao-attested-unseal/audit.jsonl",
  "otel_exporter": "none",
  "default_policy_path": "/etc/openbao-attested-unseal/default-policy.json",
  "keyring_protection_profile": "development",
  "cluster_id": "prod-eu1",
  "key_id": "root",
  "development_wrapping_key_b64": "base64-encoded-32-byte-key",
  "challenge_ttl_seconds": 120,
  "kubernetes": {
    "enabled": true,
    "token_review_audience": "bao-unseald",
    "namespace": "openbao",
    "service_account": "openbao",
    "node_evidence_ttl_seconds": 300,
    "api_timeout_seconds": 10,
    "allow_unbound_service_account_tokens": false,
    "allow_fake_node_evidence_publish": false
  }
}
```

## Out-Of-Cluster Test Config

Use explicit Kubernetes API settings for tests that run the broker outside the
cluster or against a fake API server.

```json
{
  "kubernetes": {
    "enabled": true,
    "api_server": "https://127.0.0.1:6443",
    "ca_cert_file": "/tmp/kubernetes-ca.crt",
    "bearer_token_file": "/tmp/reviewer-token",
    "token_review_audience": "bao-unseald",
    "namespace": "openbao",
    "service_account": "openbao",
    "node_evidence_ttl_seconds": 30,
    "api_timeout_seconds": 5,
    "allow_unbound_service_account_tokens": false,
    "allow_fake_node_evidence_publish": false
  }
}
```

## Development Policy

The Kubernetes verifier normalizes the policy subject as
`<namespace>.<serviceAccount>`. For an OpenBao Pod running as service account
`openbao` in namespace `openbao`, the beta development policy subject is
`openbao.openbao`.

```json
{
  "policy_id": "development",
  "mode": "development-subject",
  "development_subjects": ["openbao.openbao"]
}
```

This policy mode is a temporary beta policy surface. It authorizes a normalized
subject after provider verification. It is not a general-purpose authorization
language.

## Node Evidence Fixture

The current fake/local node evidence fixture shape is:

```json
{
  "cluster_id": "prod-eu1",
  "node_name": "node-a",
  "node_uid": "node-uid",
  "provider": "fake-local",
  "evidence_hash": "sha256:5c8f3b0c8b2f16b8707262c3516fb5d57f5b8f587f4891dfb214f01e0e4f7d72",
  "collected_at": "2026-06-29T20:00:00Z",
  "expires_at": "2026-06-29T20:05:00Z"
}
```

`fake-local` evidence only exercises broker policy behavior. It does not prove
TPM identity, Secure Boot, measured boot, confidential launch, or platform
anti-cloning.

For local broker tests, publish synthetic node evidence through the broker
admin API:

```sh
bao-unsealctl k8s publish-node \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

The current admin publish path writes to the broker's process-local node
evidence cache and requires `allow_fake_node_evidence_publish = true` in the
broker Kubernetes config. Evidence is lost when the broker restarts and is not
a durable diagnostic API.

## OpenBao Seal Config

The current plugin-side broker config still requires `node_id` and uses it for
development-subject evidence:

```hcl
seal "attested-unseal" {
  mode                 = "broker"
  broker_addr          = "bao-unseald.openbao.svc:8443"
  cluster_id           = "prod-eu1"
  node_id              = "openbao.openbao"
  evidence_mode        = "kubernetes-workload"
  kubernetes_token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token"
}
```

`kubernetes_token_file` can be omitted for standard in-cluster mounts. It is
shown here to make the token source explicit.

In this beta profile, `node_id` is challenge correlation input and should equal
the normalized Kubernetes subject. The Kubernetes verifier still derives the
actual policy subject from the TokenReview result, not from `node_id`.
