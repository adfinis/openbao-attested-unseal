# Broker Configuration

`bao-unseald` reads JSON configuration in M2.

```json
{
  "listen_address": "127.0.0.1:8443",
  "tls_cert_file": "/etc/openbao-attested-unseal/tls.crt",
  "tls_key_file": "/etc/openbao-attested-unseal/tls.key",
  "client_ca_file": "/etc/openbao-attested-unseal/clients.crt",
  "require_client_cert": true,
  "sqlite_path": "/var/lib/openbao-attested-unseal/broker.db",
  "audit_file_path": "/var/log/openbao-attested-unseal/audit.jsonl",
  "audit_fsync": false,
  "otel_exporter": "none",
  "default_policy_path": "/etc/openbao-attested-unseal/default-policy.json",
  "keyring_protection_profile": "development",
  "cluster_id": "prod-eu1",
  "key_id": "root",
  "development_wrapping_key_b64": "base64-encoded-32-byte-key",
  "challenge_ttl_seconds": 120,
  "kubernetes": {
    "enabled": true,
    "api_server": "https://kubernetes.default.svc",
    "ca_cert_file": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "bearer_token_file": "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "token_review_audience": "bao-unseald",
    "namespace": "openbao",
    "service_account": "openbao",
    "node_evidence_ttl_seconds": 300,
    "node_evidence_retention_seconds": 86400,
    "api_timeout_seconds": 10,
    "allow_unbound_service_account_tokens": false,
    "allow_fake_node_evidence_publish": false,
    "node_evidence_publish_providers": ["generic-tpm2-quote"],
    "node_evidence_tpm_policies": {
      "worker-a": {
        "node_uid": "2e913a61-62f6-4dcb-98c6-302deda22d2d",
        "policy": {
          "mode": "tpm-only",
          "enrolled_ak_public_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        }
      }
    },
    "node_evidence_publishers": {
      "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd": {
        "node_names": ["worker-a"]
      }
    }
  }
}
```

`allow_plaintext_for_tests` disables TLS only for test harnesses. Production
broker listeners should use TLS and normally set `require_client_cert`.

`audit_fsync` defaults to `false`. That avoids a forced disk flush for every
broker decision, but the most recent audit lines can be lost during host or
filesystem failure. Set it to `true` when durability is more important than
decision latency.

`otel_exporter` supports `none` and `stdout` in M2. `none` keeps
instrumentation active without installing an exporter. `stdout` emits JSON
traces and metrics to stdout for local validation.

The optional `kubernetes` block is disabled by default. When enabled, the
broker validates the TokenReview audience, namespace, service account, and node
evidence freshness window. `node_evidence_retention_seconds` controls how long
stale node evidence remains available for diagnostics before admin publish/list
operations prune it. Pod-bound service account tokens are required unless
`allow_unbound_service_account_tokens` is explicitly set to `true`. With
pod-bound tokens, the broker also performs an independent Pod API lookup and
rejects evidence if the token pod UID or node name does not match the live Pod.
Node evidence and workload evidence diagnostics return only operator metadata:
cluster, node name, optional node UID, provider, evidence hash, timestamps,
status, verified subject, and sanitized workload placement. They do not echo
submitted workload tokens, raw evidence payloads, raw claims, broker error
payloads, policy fields, or raw evidence bodies.

`allow_fake_node_evidence_publish` enables the temporary `fake-local` admin
publish path used by kind and local labs. Leave it disabled outside test
deployments.

`node_evidence_publish_providers` is the explicit allow-list for non-fake node
evidence published through the broker admin API. The supported provider is
`generic-tpm2-quote`. Enabling it requires a `node_evidence_tpm_policies` entry
for each enrolled node name. Each entry binds the Kubernetes node UID to an
enrolled attestation-key public hash and TPM policy.

The agent first requests a single-use broker challenge, collects a raw TPM
quote over that nonce, and submits the raw evidence. The broker verifies the
challenge, quote signature and shape, PCR digest, node UID, enrolled AK, and
configured policy. It assigns the collection and expiry times, caps the
requested TTL, and persists only operator-safe metadata plus a SHA-256 digest
of the submitted payload. The raw quote is not retained or returned by
diagnostic APIs.

`node_evidence_publishers` is the TPM publisher role mapping. Each key is the
lowercase `sha256:` digest of a client certificate's DER encoding, and each
value lists the node names that certificate may challenge and publish for. The
generic TPM provider requires TLS, client-certificate verification, and at
least one authorized publisher for every enrolled node. Obtain the hex digest
for a PEM certificate with:

```sh
openssl x509 -in agent.crt -outform DER | shasum -a 256
```

The `tpm-only` policy proves freshness, quote integrity, and possession of the
enrolled AK. It does not claim Secure Boot. A `secureboot` policy additionally
requires `provider_profile = "generic-pc-secureboot"` and a `pcr_policy` whose
selection includes PCR 7 and whose enrolled digest matches the quoted values.
The certificate role is deliberately independent of the AK enrollment: mTLS
authorizes which agent may submit for a node, while TPM verification proves the
submitted quote came from the enrolled AK and satisfies policy.

See [Kubernetes Profile Examples](kubernetes-profile.md) for the preview
Kubernetes profile contract and plugin evidence settings.

`api_server`, `ca_cert_file`, and `bearer_token_file` are optional for
in-cluster deployments. If omitted, `bao-unseald` derives the API endpoint from
the Kubernetes service environment and uses the mounted service account token
and CA file. Set them explicitly for out-of-cluster tests or non-standard
mount paths.

The M2 policy document is intentionally narrow:

```json
{
  "policy_id": "development",
  "mode": "development-subject",
  "development_subjects": ["node-a"]
}
```

`development-subject` is the only workload authorization policy mode. TPM node
evidence uses the separate per-node policies described above; it does not turn
the workload policy into a general-purpose authorization language.

## OpenBao Seal Configuration

Broker mode lets the KMS plugin call `bao-unseald` on an internal trusted
network instead of loading local TPM state:

```hcl
seal "attested-unseal" {
  mode        = "broker"
  broker_addr = "bao-unseald.openbao.svc:8201"
  cluster_id  = "prod-eu1"
  node_id     = "node-a"
}
```

`node_id` is the subject presented to the broker challenge flow. In the current
development policy profile it must match an allowed development subject or a
subject loaded from the default policy file.

Production broker connections should use TLS, and normally mTLS:

```hcl
seal "attested-unseal" {
  mode                   = "broker"
  broker_addr            = "bao-unseald.openbao.svc:8201"
  broker_ca_cert         = "/etc/openbao-attested-unseal/ca.crt"
  broker_tls_server_name = "bao-unseald.openbao.svc"
  broker_client_cert     = "/etc/openbao-attested-unseal/client.crt"
  broker_client_key      = "/etc/openbao-attested-unseal/client.key"
  cluster_id             = "prod-eu1"
  node_id                = "node-a"
}
```

`broker_plaintext = "true"` is available for local Docker and test harnesses
only. It should not be used for production broker listeners.
