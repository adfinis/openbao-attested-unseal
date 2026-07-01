# Kubernetes Profile Runbook

Status: draft

Last reviewed: 2026-06-30

This runbook covers the beta Kubernetes broker profile. It assumes
`bao-unseald` is configured with the Kubernetes verifier and that node evidence
is supplied by the current fake/local test path or a future node evidence
publisher.

## Preflight

Validate broker configuration before starting the daemon:

```sh
bao-unseald config validate -config broker.json
```

Check the local broker database after bootstrap:

```sh
bao-unsealctl status -state /var/lib/openbao-attested-unseal/broker.db
```

For Kubernetes profile testing, confirm these inputs before investigating
policy behavior:

- `kubernetes.enabled` is `true`;
- `token_review_audience` matches the projected token audience;
- `namespace` and `service_account` match the OpenBao workload;
- the default policy contains `namespace.serviceAccount`, such as
  `openbao.openbao`;
- the OpenBao seal config sets `evidence_mode = "kubernetes-workload"`;
- fresh node evidence exists for the Pod's scheduled node;
- the node evidence `node_uid` matches the TokenReview node UID when both are
  present.

## Failure Triage

| Symptom | Likely cause | Operator action |
| --- | --- | --- |
| `attestation verification failed` before policy evaluation | TokenReview, audience, service account, Pod lookup, or pod binding failed | Check Kubernetes API reachability, broker service account RBAC, projected token audience, and Pod UID. |
| `subject evidence is required` | Plugin sent no recognized evidence | Confirm the caller is using the intended evidence mode and that the broker verifier matches that mode. |
| `subject is not allowed` | Verified subject is absent from the development policy | Add the normalized subject, for example `openbao.openbao`, then restart or reload through the supported flow. |
| `subject is revoked` | Broker subject was revoked | Re-enroll or intentionally keep the subject denied. |
| `node evidence is missing` | No evidence record for the Pod node | Publish fresh node evidence for that node or investigate node-agent health. |
| `node evidence is stale` | Evidence expired before the request | Short term: republish evidence. Long term: tune publisher interval and `node_evidence_ttl_seconds`. |
| `node evidence does not match workload node` | TokenReview node UID and cached node evidence disagree | Treat as suspicious until scheduling, node replacement, and evidence publisher state are understood. |
| `challenge expired` | The plugin used an old broker challenge | Check clock skew and broker/plugin latency. |
| `challenge was already consumed` | Replay or retry reused a consumed challenge | Retrying should request a new challenge. Investigate repeated reuse. |

## TokenReview And Pod Lookup

The broker needs Kubernetes API access for:

- `authentication.k8s.io/v1` TokenReview;
- core/v1 Pod `get` for the configured namespace and OpenBao Pod name.

The beta RBAC manifest in `deploy/kubernetes/rbac.yaml` grants exactly those
permissions to the `openbao/bao-unseald` service account. The kind e2e test
applies that manifest and verifies that the service account can create a
TokenReview and read the OpenBao Pod, without granting broad Pod permissions
outside the OpenBao namespace.

## Node Evidence Freshness

`node_evidence_ttl_seconds` is the maximum age window accepted by broker
policy. Choose a value longer than the normal node evidence publishing interval
and shorter than the operator's acceptable exposure window after node evidence
publisher failure.

`node_evidence_retention_seconds` controls how long stale evidence remains
available for diagnostics after it expires. Broker admin publish/list operations
prune evidence whose `expires_at` is older than this retention window.

Diagnostics show node evidence metadata and evidence hashes only. They do not
show submitted raw claims, broker error payloads, policy fields, or future raw
evidence bodies.

For example:

- publisher interval: 60 seconds;
- broker TTL: 300 seconds;
- broker retention: 86400 seconds;
- expected result: one or two missed publishes do not break restart, but stale
  node evidence denies after five minutes.

The fake/local fixture path is useful for testing this behavior but is not a
security control.

In local labs, `bao-unseal-agent run` can maintain the fake/local record:

```sh
bao-unseal-agent run \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker \
  -ttl 5m \
  -interval 1m
```

During local or kind testing, seed fake node evidence explicitly:

```sh
bao-unsealctl k8s publish-node \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

Use `-ttl` to shorten stale-evidence tests. The fake publish path stores
evidence in the broker node evidence store. In normal broker runtime this store
is SQLite-backed; unit tests can use an in-memory cache. The broker must have
`allow_fake_node_evidence_publish` enabled for this command to succeed.

Check broker-side node evidence state for one node:

```sh
bao-unsealctl k8s check \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker
```

By default, `k8s check` classifies broker reachability and node evidence as
`fresh`, `stale`, `missing`, or `unavailable`.

When a workload token is available, include `-token-file` to run a broker-side
workload evidence diagnostic without wrapping or unwrapping key material:

```sh
bao-unsealctl k8s check \
  -addr 127.0.0.1:8443 \
  -plaintext \
  -cluster-id prod-eu1 \
  -node-name kind-worker \
  -token-file /var/run/secrets/kubernetes.io/serviceaccount/token \
  -format json
```

The token check can distinguish invalid or unauthenticated workload evidence,
wrong TokenReview audience, subject policy denial, and missing or stale node
evidence. It reports sanitized workload placement metadata and redacted node
evidence metadata; it does not print the token or raw evidence payload.

## Revocation

Use broker subject revocation when a workload identity should stop using the
broker immediately:

```sh
bao-unsealctl revoke subject \
  -state /var/lib/openbao-attested-unseal/broker.db \
  -subject-id openbao.openbao
```

Subject revocation blocks future broker decisions for that normalized
Kubernetes subject. It does not erase already-issued OpenBao tokens, undo an
already completed unwrap, or rotate broker wrapping keys.

If one Kubernetes node is suspected, remove or stop publishing its node
evidence first. If key material may have been exposed, rotate the broker
wrapping key as well.

## Rotation

Broker wrapping-key rotation and OpenBao root rotation are separate but related
operations. For Kubernetes profile deployments, use the same broker rotation
flow and verify restart while the OpenBao Pod is scheduled on a node with fresh
evidence.

```sh
bao-unsealctl rotate start \
  -state /var/lib/openbao-attested-unseal/broker.db

BAO_TOKEN=... bao-unsealctl rotate openbao-root \
  -state /var/lib/openbao-attested-unseal/broker.db \
  -operation-id rot_...

bao-unsealctl rotate activate \
  -state /var/lib/openbao-attested-unseal/broker.db \
  -operation-id rot_...

bao-unsealctl rotate verify-restart \
  -state /var/lib/openbao-attested-unseal/broker.db \
  -operation-id rot_...
```

Do not treat Kubernetes provider success as proof that Secure Boot, measured
boot, or TPM policy survived rotation. Those checks belong to the node evidence
provider.

## Current Gaps

- The tracked Kubernetes manifests are beta/lab examples and need production
  hardening.
- There is no production node attestation agent yet.
- `fake-local` node evidence is for tests and local development only.
