# Kubernetes Profile Examples

Status: draft

Last reviewed: 2026-06-29

These examples show the current Kubernetes runtime profile contract for
`bao-unseald`. They are intentionally beta examples, not production deployment
manifests.

## Current Boundary

The broker can verify Kubernetes workload evidence when it receives an evidence
envelope with:

- provider `ATTESTATION_PROVIDER_KUBERNETES_WORKLOAD`;
- format `openbao-attested-unseal.kubernetes-workload.v1`;
- a projected service account token in the evidence payload.

The OpenBao KMS plugin does not yet collect the projected service account token
or emit Kubernetes workload evidence. The current plugin broker path still emits
development-subject evidence from `node_id`. A full OpenBao-on-Kubernetes e2e
therefore needs a follow-on plugin evidence collection slice before manifests
can prove the complete path.

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
    "allow_unbound_service_account_tokens": false
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
    "allow_unbound_service_account_tokens": false
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

## OpenBao Seal Config

The current plugin-side broker config still requires `node_id` and uses it for
development-subject evidence:

```hcl
seal "attested-unseal" {
  mode        = "broker"
  broker_addr = "bao-unseald.openbao.svc:8443"
  cluster_id  = "prod-eu1"
  node_id     = "openbao.openbao"
}
```

Once plugin-side Kubernetes evidence collection lands, `node_id` should no
longer be the source of the Kubernetes workload subject. It may remain as a
challenge correlation or compatibility field, depending on the final wrapper
contract.
