---
title: "Broker Configuration"
description: "Current bao-unseald broker configuration fields."
weight: 20
---

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
    "enabled": false,
    "token_review_audience": "bao-unseald",
    "namespace": "openbao",
    "service_account": "openbao",
    "node_evidence_ttl_seconds": 300,
    "allow_unbound_service_account_tokens": false
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
evidence freshness window. Pod-bound service account tokens are required unless
`allow_unbound_service_account_tokens` is explicitly set to `true`.

The M2 policy document is intentionally narrow:

```json
{
  "policy_id": "development",
  "mode": "development-subject",
  "development_subjects": ["node-a"]
}
```

Only `development-subject` mode is implemented in M2. Real attestation policy
arrives in later milestones.
