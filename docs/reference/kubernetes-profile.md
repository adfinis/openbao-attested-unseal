# Kubernetes Profile Examples

Status: draft

Last reviewed: 2026-08-12

These examples show the current Kubernetes runtime profile contract for
`bao-unseald`. They are intentionally preview examples, not production deployment
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

`node_id` is still required by the broker challenge path. For the current preview
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
    "node_evidence_retention_seconds": 86400,
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
    "node_evidence_retention_seconds": 3600,
    "api_timeout_seconds": 5,
    "allow_unbound_service_account_tokens": false,
    "allow_fake_node_evidence_publish": false
  }
}
```

## Development Policy

The Kubernetes verifier normalizes the policy subject as
`<namespace>.<serviceAccount>`. For an OpenBao Pod running as service account
`openbao` in namespace `openbao`, the preview development policy subject is
`openbao.openbao`.

```json
{
  "policy_id": "development",
  "mode": "development-subject",
  "development_subjects": ["openbao.openbao"]
}
```

This policy mode is a temporary preview policy surface. It authorizes a normalized
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

`bao-unseal-agent publish-once`, `bao-unseal-agent run`, and the reusable node
evidence publisher primitive also support the `generic-tpm2-quote` provider.
The agent requests a single-use challenge from the broker, collects a raw TPM
2.0 quote over the broker nonce, performs a local self-check, and submits the
raw evidence. The broker verifies the nonce and challenge ID, AK signature,
quote shape, PCR selection and digest, configured node UID, enrolled AK public
hash, and TPM policy. Only then does it assign freshness and store a verified
metadata projection plus the payload digest. Node AK policy and publisher scope
are revisioned broker state. Authenticated `node-evidence-admin` operations
enroll or revoke that state, and every TPM challenge and publish resolves the
active enrollment for the submitted node.

Broker diagnostics expose only node evidence metadata: cluster, node name,
optional node UID, provider, evidence hash, timestamps, and freshness status.
They do not return submitted raw claim lists, broker error payloads, policy
fields, or raw evidence bodies.

For local broker tests, publish synthetic node evidence through the broker
admin API:

```sh
bao-unseal-agent publish-once \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

For local long-running tests, keep evidence fresh with:

```sh
bao-unseal-agent run \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker \
  -ttl 5m \
  -interval 1m
```

For TPM-backed evidence, enable `generic-tpm2-quote` in broker
`node_evidence_publish_providers` and configure a control-plane certificate
with the `node-evidence-admin` role. Write the approved TPM policy to a file:

```json
{
  "mode": "tpm-only",
  "enrolled_ak_public_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Then enroll the node UID, policy, and publisher certificate through the running
broker:

```sh
bao-unsealctl k8s nodes enroll \
  -addr bao-unseald.openbao.svc:8443 \
  -ca-cert broker-ca.crt \
  -client-cert operator.crt \
  -client-key operator.key \
  -cluster-id prod-eu1 \
  -node-name "$NODE_NAME" \
  -node-uid "$NODE_UID" \
  -tpm-policy node-tpm-policy.json \
  -publisher-cert-sha256 "sha256:$PUBLISHER_CERT_DIGEST" \
  -reason "approve node evidence publisher CHG-1234"
```

Re-enrollment replaces the node policy and publisher set, increments the trust
revision, and invalidates previously verified evidence. This provider requires
TLS with client-certificate verification. After enrollment, run the agent with
TPM flags:

```sh
bao-unseal-agent run \
  -addr bao-unseald.openbao.svc:8443 \
  -cluster-id prod-eu1 \
  -node-name "$NODE_NAME" \
  -node-uid "$NODE_UID" \
  -provider-id generic-tpm2-quote \
  -tpm-device /dev/tpmrm0 \
  -tpm-pcr-bank sha256 \
  -tpm-pcrs 7 \
  -ttl 5m \
  -interval 1m
```

The operator CLI keeps a lab-oriented helper for the same fake-local publish
path:

```sh
bao-unsealctl k8s publish-node \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

The admin publish path verifies a challenge-bound submission before writing to
the broker node evidence store. It requires either
`allow_fake_node_evidence_publish = true` for `fake-local`, or both the
`generic-tpm2-quote` allow-list entry, an active broker enrollment, and an
authorized mTLS publisher certificate scoped to that node. In normal broker
runtime this store is SQLite-backed; in unit tests it can be an in-memory
cache.

Use `bao-unsealctl k8s check` to classify broker-side node evidence state for
one node:

```sh
bao-unsealctl k8s check \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

By default, the check covers broker admin availability plus fresh, stale, and
missing node evidence. Add `-token-file` to ask the broker to evaluate a
Kubernetes workload token through the diagnostic admin API without wrapping or
unwrapping key material:

```sh
bao-unsealctl k8s check \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker \
  -token-file /var/run/secrets/kubernetes.io/serviceaccount/token
```

The workload check reports the verified subject, sanitized workload placement
metadata, workload decision, and redacted node evidence metadata. It does not
return the workload token, raw evidence payload, normalized claim list, or
raw node evidence bodies.

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

In this preview profile, `node_id` is challenge correlation input and should equal
the normalized Kubernetes subject. The Kubernetes verifier still derives the
actual policy subject from the TokenReview result, not from `node_id`.
