# Kubernetes Provider Profile

Status: draft

Last reviewed: 2026-08-11

This profile describes the first Kubernetes-oriented broker mode. It combines
Kubernetes workload identity with node evidence verified by the broker. It is
intended for the preview project shape. The repository includes preview RBAC
and deployment manifests plus a standalone node-agent TPM quote publisher, but
enrollment operations, broader control-plane authorization, and packaging still
need production hardening.

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
| First production-shaped provider | `generic-tpm2-quote` raw TPM 2.0 quotes verified by the broker against an enrolled AK and policy |
| Future node evidence providers | SPIFFE/SPIRE, KubeVirt/libvirt, confidential node, or cloud profile evidence |
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

The Kubernetes workload profile does not claim Secure Boot, measured boot,
TPM identity, vTPM anti-cloning, confidential launch, or node integrity by
itself. Those claims depend on the configured node-evidence policy. The generic
TPM provider can claim freshness, quote integrity, and possession of an
enrolled AK in `tpm-only` mode. It claims the enrolled PCR 7 state only when a
matching `secureboot` policy is explicitly configured; it does not infer
Secure Boot from the platform hint alone.

The `fake-local` node evidence profile is not a production security boundary.
It exists so tests and local development can exercise policy behavior without
requiring Kubernetes node TPM access or a cloud attestation service.

The `generic-tpm2-quote` node evidence publisher is stronger than fake-local:
the broker issues a single-use challenge, and the agent submits a raw TPM quote
over the broker nonce. The broker verifies challenge binding, AK signature,
quote shape, PCR selection and digest, the configured node UID, the enrolled AK
public hash, and the TPM policy. The agent's local verification is only a
self-check. The broker assigns freshness and stores only the provider identity
and SHA-256 evidence digest. Enrollment and revocation are currently static
configuration. TPM challenge and publish calls require a configured mTLS client
certificate fingerprint whose role includes the submitted node name.

## Trust Boundaries

The following components are inside the trusted computing base for this
profile:

- Kubernetes API server and TokenReview implementation;
- Kubernetes scheduler, Pod API state, and service account token issuer;
- kubelet and container runtime on the OpenBao node;
- broker daemon and its configuration;
- TPM and enrolled attestation key used by the node-evidence agent;
- node evidence agent as the transport path to that TPM; its submitted claims,
  timestamps, and digest are not trusted without broker verification;
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

The separate node-evidence refresh flow is:

1. The agent requests a challenge for its cluster, node name, node UID, and
   provider.
2. The broker checks configured cluster and node enrollment, then returns a
   short-lived nonce and challenge ID only if the mTLS client certificate is
   authorized for that node.
3. The agent quotes the configured PCRs and submits the raw evidence.
4. The broker verifies the quote and policy, consumes the challenge once, caps
   the requested TTL, and stores only the verified projection and payload
   digest.

## Configuration

The broker `kubernetes` block enables this profile:

```json
{
  "require_client_cert": true,
  "kubernetes": {
    "enabled": true,
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
| `evidence_hash` | Broker-computed SHA-256 digest of the submitted payload. |
| `collected_at` | Broker-assigned verification time. |
| `expires_at` | Broker-assigned freshness end time, capped by configuration. |

Diagnostics and audit records retain metadata and evidence hashes, but they do
not echo submitted raw claim lists, broker error payloads, policy fields, or
raw evidence bodies.

For the current fake/local path, the provider is `fake-local` and the evidence
payload is a deterministic, challenge-bound fixture. The broker hashes it only
after verifying that binding. This provider makes no hardware or platform
claim.

For the current generic TPM path, the provider is `generic-tpm2-quote` and the
evidence hash is the broker-computed `sha256:` digest of the raw TPM evidence
payload. The broker verifies the payload but does not retain or return it.

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
- reusable generic TPM quote publisher contract with local self-checks;
- broker-issued TPM challenges, raw quote verification against enrolled AK and
  node UID, certificate-role and node-scope authorization, TTL capping,
  digest-only persistence, and replay denial;
- broker admin publish/list APIs, `bao-unseal-agent publish-once`,
  `bao-unseal-agent run`, and `bao-unsealctl k8s publish-node` for synthetic
  local node evidence;
- broker provider allow-listing and per-node TPM policy validation for
  `generic-tpm2-quote` publishing;
- broker admin evidence diagnostics and `bao-unsealctl k8s check -token-file`
  for sanitized workload-token and node-evidence policy results.

## Unsupported Claims

This profile does not yet provide:

- production-hardened Kubernetes packaging;
- authenticated and audited AK enrollment or revocation operations;
- distinct roles for the remaining control-plane and diagnostic RPCs;
- a measured-boot policy-update workflow;
- EK certificate-chain or manufacturer provenance verification;
- SPIFFE/SPIRE SVID verification;
- AWS, Azure, or Google trusted-launch verification;
- KubeVirt or libvirt vTPM clone and migration policy;
- a Secure Boot claim without an enrolled matching PCR policy;
- a measured-boot claim in the current TPM policy implementation.
