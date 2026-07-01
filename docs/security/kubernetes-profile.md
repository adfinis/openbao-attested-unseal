# Kubernetes Provider Profile

Status: draft

Last reviewed: 2026-06-29

This profile describes the first Kubernetes-oriented broker mode. It combines
Kubernetes workload identity with node evidence already trusted by the broker.
It is intended for the beta project shape. The repository includes beta RBAC
and deployment manifests, but they still need production hardening and a real
node attestation agent.

See [Kubernetes Profile Examples](../reference/kubernetes-profile.md) for
configuration snippets and
[Kubernetes Profile Runbook](../operations/kubernetes-profile-runbook.md) for
failure triage, revocation, and rotation notes.

## Profile Summary

| Field | Value |
| --- | --- |
| Profile name | `kubernetes-runtime` |
| Supported platform target | Kubernetes `1.35+` |
| Workload evidence | Projected service account token verified through TokenReview |
| Placement evidence | Live Pod API lookup for pod UID and scheduled node |
| Node evidence | Broker-local fresh node evidence cache |
| First node evidence provider | `fake-local` fixtures for tests and development only |
| Future node evidence providers | TPM quote, vTPM quote, KubeVirt/libvirt, confidential node, or cloud profile evidence |
| Runtime network dependency | Kubernetes API on the internal or trusted network |
| External network dependency | None in the core profile |

## Security Claim

When configured with pod-bound service account tokens and fresh node evidence,
the broker can claim:

- the OpenBao workload token is valid for the configured audience;
- the workload belongs to the configured namespace and service account;
- the token is bound to a live Pod UID;
- the live Pod is scheduled on the node named in broker policy input;
- the node has fresh evidence accepted by the configured node evidence profile;
- stale or missing node evidence denies wrap and unwrap operations.

The profile does not claim Secure Boot, measured boot, TPM identity, vTPM
anti-cloning, confidential launch, or node integrity by itself. Those claims
must come from the node evidence provider and must be documented by that
provider profile.

The `fake-local` node evidence profile is not a production security boundary.
It exists so tests and local development can exercise policy behavior without
requiring Kubernetes node TPM access or a cloud attestation service.

## Trust Boundaries

The following components are inside the trusted computing base for this
profile:

- Kubernetes API server and TokenReview implementation;
- Kubernetes scheduler, Pod API state, and service account token issuer;
- kubelet and container runtime on the OpenBao node;
- broker daemon and its configuration;
- node evidence publisher or test fixture that writes broker-trusted node
  evidence;
- platform administrators who can mutate nodes, Pods, service accounts, or
  token issuer state.

A malicious tenant workload in the same cluster should not be able to satisfy
this profile unless it can obtain the configured OpenBao service account token,
alter Pod API state, alter node evidence, or control a trusted component above.

## Runtime Flow

1. OpenBao calls the KMS plugin for wrap or unwrap.
2. The plugin calls `bao-unseald` with Kubernetes evidence.
3. The broker verifies the service account token through TokenReview.
4. The broker checks audience, namespace, service account, and pod-bound claims.
5. The broker looks up the live Pod and verifies the token pod UID.
6. The broker correlates the Pod node with fresh node evidence.
7. Policy allows or denies the operation before key material is used.

## Configuration

The broker `kubernetes` block enables this profile:

```json
{
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

For in-cluster deployments, `api_server`, `ca_cert_file`, and
`bearer_token_file` may be omitted. The broker derives the API endpoint from
the Kubernetes service environment and uses the mounted service account token
and CA file.

Out-of-cluster tests can set those fields explicitly.

## Node Evidence Contract

The broker policy uses these node evidence fields:

| Field | Purpose |
| --- | --- |
| `cluster_id` | Binds evidence to one OpenBao cluster. |
| `node_name` | Correlates workload placement with evidence. |
| `node_uid` | Optional stronger match against TokenReview node UID. |
| `provider` / `provider_id` | Identifies the node evidence profile. |
| `evidence_hash` | Auditable digest or fixture identifier. |
| `collected_at` | Evidence freshness start time. |
| `expires_at` | Evidence freshness end time. |

Diagnostics and audit records retain metadata and evidence hashes, but they do
not echo submitted raw claim lists, broker error payloads, policy fields, or
future raw evidence bodies.

For the current fake/local path, the provider is `fake-local` and the evidence
hash is only a deterministic fixture value. A production provider must define
what is hashed, which trust root verifies it, and which claim strength it
supports.

## Revocation And Rotation

This profile has two independent revocation levers:

- revoke or remove the workload subject so policy denies future operations;
- let node evidence expire or remove it from the broker evidence source.

If a node is believed compromised, denial through broker policy is the immediate
control. Key rotation is still the durable boundary when old key material may
have been exposed or when previously allowed nodes should no longer decrypt old
seal blobs.

OpenBao root rotation and broker wrapping-key rotation remain separate
operations. The Kubernetes provider profile only decides whether the broker may
use configured key material for a request.

## Failure Modes

| Failure | Expected result |
| --- | --- |
| TokenReview API unavailable | Attestation verification fails. |
| TokenReview denies token | Request is unauthenticated. |
| Audience mismatch | Attestation verification fails. |
| Namespace or service account mismatch | Attestation verification fails. |
| Pod-bound claims missing | Attestation verification fails unless unbound tokens are explicitly allowed. |
| Live Pod lookup fails | Attestation verification fails. |
| Pod UID mismatch | Attestation verification fails. |
| Pod has no scheduled node | Attestation verification fails. |
| Node evidence missing | Policy denies with attestation failed. |
| Node evidence stale | Policy denies with attestation failed. |
| Node UID mismatch | Policy denies with attestation failed. |

## Test Coverage

Current tests cover:

- TokenReview request shape and sanitized TokenReview errors;
- live Pod lookup request shape and sanitized Pod lookup errors;
- acceptance with TokenReview plus independent Pod lookup;
- denial on pod UID mismatch and node mismatch;
- runtime broker wiring against a fake Kubernetes API server;
- policy allow, stale evidence denial, and node UID mismatch using
  fake/local node evidence fixtures;
- reusable fake-local node evidence publisher contract;
- broker admin publish/list APIs, `bao-unseal-agent publish-once`,
  `bao-unseal-agent run`, and `bao-unsealctl k8s publish-node` for synthetic
  local node evidence;
- broker admin evidence diagnostics and `bao-unsealctl k8s check -token-file`
  for sanitized workload-token and node-evidence policy results.

## Unsupported Claims

This profile does not yet provide:

- production-hardened Kubernetes packaging;
- a production node attestation agent;
- SPIFFE/SPIRE SVID verification;
- AWS, Azure, or Google trusted-launch verification;
- KubeVirt or libvirt vTPM clone and migration policy;
- a Secure Boot or measured boot claim without a supporting node provider.
