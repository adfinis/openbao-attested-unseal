---
title: "Threat Model"
description: "Threat model for OpenBao attested unseal with TPM as one backend."
weight: 10
---

# Threat Model: `openbao-attested-unseal`

Status: draft

Last reviewed: 2026-06-28

## Purpose

OpenBao 2.6 introduces external `kms` plugins for Auto Unseal. This document
evaluates whether an attested, node-bound KMS plugin with TPM as one backend is
an appropriate direction for on-premises, VM based, and Kubernetes based
OpenBao clusters that do not want to depend on cloud KMS, a separate OpenBao
Transit cluster, static auto unseal, or manual Shamir unseal during normal
restarts.

The goal is not to prove that a TPM-only plugin should exist. The goal is to
define which security claims are honest for each deployment model and identify
where a broader attested unseal design, such as an attestation backed broker, is
more robust.

## Baseline Assumptions

- OpenBao's Auto Unseal path correctly uses the configured KMS wrapper to
  protect root or recovery material.
- OpenBao storage snapshots and backups may be copied by operators or attackers.
- Recovery custodians can protect offline recovery shares better than the
  OpenBao nodes can protect always-available runtime state.
- This is an open source project. The product cannot assume which platform
  administrators are inside the trusted computing base for all deployments.
  Each deployment profile must state whether hypervisor, cloud, Kubernetes, or
  node administrators are trusted.
- In ordinary VM environments, the hypervisor or cloud platform administrator
  is effectively inside the trusted computing base unless attestation and policy
  explicitly narrow that trust.
- In Kubernetes environments, a pod should normally be considered replaceable,
  while TPM sealed state is node-bound. Any design that binds OpenBao to a
  specific TPM must make that scheduling constraint explicit.
- A runtime network dependency is acceptable when it stays on an internal or
  otherwise trusted network. External network dependencies are out of scope for
  the primary design.
- The target audience includes controlled VM estates, mainstream Kubernetes,
  and edge or appliance deployments.
- The first version should prefer clear security claims over broad platform
  coverage.

## Design Inputs

The current design direction is:

- The project should be an attested unseal project with TPM as one backend, not
  only a TPM plugin.
- First-class attestation support is preferred for major VM and Kubernetes
  environments, including AWS NitroTPM, Azure Trusted Launch, Google Shielded
  VM, on-prem libvirt or KubeVirt, and confidential container environments.
- Enrollment should preferably be possible by a single operator in the normal
  case, with stronger quorum modes available for higher assurance deployments.
- Recovery should prefer recovery enrollment onto new TPMs or attested
  identities, rather than raw export of `K`.
- Node revocation without rotating `K` remains an explicit design question
  because the answer depends on whether nodes keep a local TPM sealed copy of
  `K`.

## Summary Position

An attested unseal design is the better umbrella for the target audience,
because the project needs to cover controlled VM estates, mainstream
Kubernetes, and edge or appliance deployments.

A local TPM mode is still a reasonable fit for a narrower class of deployments:

- physical servers with a real TPM;
- edge or appliance deployments where node identity is intentionally stable;
- tightly managed VMs where the operator accepts the hypervisor as part of the
  trusted computing base;
- disconnected sites where runtime network dependency is unacceptable.

Local TPM-only unseal is not a strong default for mainstream Kubernetes or
ordinary VM based OpenBao clusters. In those environments, the actual trust
boundary is usually the virtualization or orchestration platform, not the local
TPM interface visible to the OpenBao process. For VM and Kubernetes first
deployments, the more robust direction is an attestation backed unseal broker,
with TPM or vTPM evidence as one input to policy.

## OpenBao Plugin Context

OpenBao 2.6.0 beta added a `kms` plugin type for Auto Unseal. Operators can
register a KMS plugin with a `plugin "kms" "name"` stanza and use that name in
the `seal "name"` stanza. The plugin implements the `go-kms-wrapping` wrapper
contract used by OpenBao's Auto Unseal path.

For this threat model, the relevant plugin behavior is:

- OpenBao stores encrypted seal blobs in its normal storage backend.
- The KMS wrapper encrypts and decrypts OpenBao root or recovery material.
- `BlobInfo.KeyInfo.KeyId` identifies the wrapping key used for a blob.
- During startup, OpenBao must be able to call the wrapper's decrypt path before
  the node becomes unsealed.

## Candidate Designs

### Local TPM Mode

The local TPM mode under discussion is:

```text
OpenBao shared storage:
  encrypted seal blobs

Each OpenBao node:
  TPM 2.0 or vTPM
  TPM sealed copy of the cluster wrapping key
  KMS plugin binary
  local TPM KMS state directory
```

The same cluster wrapping key `K` is sealed into each approved node's TPM or
vTPM. OpenBao seal blobs are encrypted with `K`. Copying the OpenBao storage
snapshot to an arbitrary machine should not be enough to unseal the cluster
unless that machine also has an approved TPM sealed copy of `K`, or an operator
uses the recovery process.

This mode has no runtime network dependency, but it has weaker revocation and
node replacement properties because enrolled nodes retain local access to `K`.

### Attested Broker Mode

The attested broker mode is:

```text
OpenBao shared storage:
  encrypted seal blobs

Each OpenBao node:
  KMS plugin binary
  platform, TPM, vTPM, or workload attestation evidence

Internal trusted network:
  unseal broker
  policy engine
  encrypted wrapping key material or key release service
```

The broker verifies node, platform, and workload evidence before allowing the
plugin to decrypt or obtain the wrapping key material needed by OpenBao. This
mode accepts an internal runtime network dependency in exchange for stronger
central policy, audit, revocation, and node replacement behavior.

External network dependencies are not part of the primary design. Cloud-native
attestation services may be supported by specific deployment profiles, but the
core design should be able to run on a trusted internal network.

## Protected Assets

- OpenBao barrier root key and recovery material passed through the Auto Unseal
  wrapper.
- Cluster wrapping key `K` and historical wrapping keys.
- TPM sealed objects or vTPM persistent state that protect `K`.
- Recovery escrow shares for `K`.
- Enrollment requests, enrollment grants, and node approval records.
- Plugin binary, plugin configuration, and local state under `state_path`.
- OpenBao storage snapshots and backups.
- Audit records for enrollment, rotation, recovery, and policy updates.

## Security Goals

1. A copied OpenBao storage snapshot alone cannot be used to unseal the cluster.
2. A copied local TPM KMS state directory alone cannot reveal `K`.
3. An unenrolled node cannot decrypt existing OpenBao seal blobs.
4. An enrolled node can auto-unseal using either local TPM state or an internal
   trusted-network broker, depending on the selected deployment profile.
5. Loss of one node does not prevent HA peers from unsealing.
6. Loss of all enrolled TPM copies is recoverable only with the configured
   recovery escrow threshold.
7. Rotation preserves the ability to decrypt old seal blobs until they are no
   longer needed.
8. Policy modes are explicit and auditable. Operators can tell whether a key is
   bound only to a TPM, to Secure Boot PCRs, or to stricter measurements.
9. The implementation does not accidentally degrade into static key auto-unseal
   by writing `K` to disk, logs, environment variables, crash dumps, or command
   output.
10. No primary design path requires an external network dependency.

## Non-Goals

- Protecting against a fully compromised running OpenBao process.
- Protecting against a malicious root user on an already unsealed node.
- Providing cloud KMS or HSM style durability from a local TPM alone.
- Making ordinary vTPM equivalent to physical TPM hardware.
- Solving OpenBao storage integrity or Raft consensus security.
- Replacing OpenBao recovery keys or recovery operations.
- Providing generic external key management in v1. The first target, if built,
  should be Auto Unseal wrapping only.

## Actors

- OpenBao operator: deploys and maintains OpenBao and the plugin.
- Recovery custodians: hold shares for the TPM KMS cluster wrapping key.
- Node administrator: controls host OS, VM, or Kubernetes node configuration.
- Platform administrator: controls hypervisor, cloud project, Kubernetes
  control plane, VM templates, snapshots, and node pools.
- Storage attacker: obtains OpenBao storage snapshots or backups.
- Node filesystem attacker: obtains plugin state files from one node.
- Network attacker: can observe or interfere with enrollment or broker traffic.
- Malicious workload tenant: has workload execution in the same Kubernetes
  cluster but should not affect OpenBao unseal.
- Supply chain attacker: attempts to replace the plugin binary, container image,
  or enrollment tooling.

## Trust Boundaries

```text
OpenBao process
  -> KMS plugin process
    -> local OS and device permissions
      -> TPM device or vTPM frontend
        -> physical TPM, hypervisor vTPM implementation, or confidential VM TCB

OpenBao process
  -> storage backend
    -> OpenBao encrypted seal blob

Lifecycle tooling
  -> recovery custodians
  -> enrollment artifacts
  -> local node state
```

The important boundary is different per deployment class:

- Physical TPM: hardware package and firmware are the relevant local root.
- Ordinary vTPM: the hypervisor and platform administrators are in the root of
  trust.
- Kubernetes with host TPM: the node OS, kubelet, container runtime, scheduling
  constraints, and device exposure policy are in the root of trust.
- Confidential VM or confidential container: the attestation root and measured
  launch environment become the meaningful policy anchors.

## Deployment Classes

| Deployment class | Expected claim strength | Notes |
| --- | --- | --- |
| Physical TPM on bare metal | Strong local anti-copy claim | Best fit for TPM-only runtime design. Rare for OpenBao clusters in many environments. |
| Appliance or edge node | Strong if node lifecycle is controlled | Good fit when operator values offline restart over elastic scheduling. |
| Ordinary VM with vTPM | Medium to weak | Depends on hypervisor controls, vTPM migration, snapshot, backup, and clone semantics. Treat platform admin as trusted. |
| Confidential VM with vTPM and attestation | Medium to strong | Better fit for attestation backed unseal than pure local unseal. |
| Kubernetes pod with host TPM device | Weak to medium | Ties pod to a node, requires careful device exposure, and conflicts with replaceable node pools. |
| Kubernetes on confidential nodes or containers | Medium to strong | Prefer attestation backed broker. Local TPM-only still struggles with pod scheduling and recovery. |
| Kubernetes with no TPM access | Not applicable | Use broker, HSM/KMIP, Transit, static seal, or Shamir. |

## Threats and Mitigations

### T1: Storage Snapshot Theft

Scenario: An attacker obtains OpenBao storage, such as a Raft snapshot or
backend backup, and tries to unseal it elsewhere.

Physical TPM claim:

- Storage alone is insufficient because the attacker lacks the TPM sealed copy
  of `K`.

Ordinary vTPM claim:

- Storage alone may still be insufficient, but the claim depends on whether the
  attacker can also obtain or clone the VM's vTPM state.

Mitigations:

- Store only encrypted seal blobs in OpenBao storage.
- Keep TPM sealed state outside storage snapshots.
- Use explicit cluster and key IDs as authenticated context.
- Document that VM/vTPM platform snapshots may change the threat model.

### T2: Node Filesystem Theft

Scenario: An attacker obtains `/var/lib/openbao/tpm-kms` from a node but not the
TPM or vTPM state.

Expected claim:

- TPM sealed objects should be useless without the matching TPM and policy.

Mitigations:

- Store TPM sealed blobs only, never raw `K`.
- Use strict file permissions owned by the OpenBao service user.
- Include metadata checks so state from another cluster or key ID fails closed.
- Treat local state backups as sensitive but not independently sufficient.

### T3: VM Clone or vTPM Clone

Scenario: A platform administrator or attacker clones a VM, including disk and
vTPM state, and runs a copy of an enrolled OpenBao node.

Expected claim:

- TPM-only does not protect against a platform that can clone the complete VM
  security state.
- This is the central weakness for ordinary VM based deployments.

Mitigations:

- State clearly that the platform administrator is trusted for ordinary vTPM.
- Prefer attestation backed broker for VM first deployments.
- Bind unseal authorization to unique platform instance identity where possible.
- Record and audit enrolled node identities.
- Consider requiring a broker or quorum re-approval after clone-sensitive
  lifecycle events.

### T4: Kubernetes Pod Rescheduling

Scenario: OpenBao runs as a pod. Kubernetes reschedules the pod to a different
node without the required TPM sealed state.

Expected claim:

- Local TPM-only conflicts with elastic pod scheduling unless node affinity and
  state management are strict.

Mitigations:

- Use node affinity and taints/tolerations for enrolled nodes.
- Use a Kubernetes device plugin or explicit host device configuration for TPM
  access.
- Treat each enrolled node as less disposable infrastructure, not fully elastic
  cluster capacity.
- Prefer attestation backed broker for dynamic node pools.

### T5: Host TPM Shared Across Workloads

Scenario: A Kubernetes node exposes the same TPM device to privileged workloads,
or another workload can interfere with TPM access.

Expected claim:

- A host TPM is a node level resource, not naturally a pod level isolated
  resource.

Mitigations:

- Avoid sharing the TPM resource across unrelated workloads.
- Use a dedicated node pool for OpenBao.
- Use device plugin allocation where practical.
- Require Pod Security Admission or equivalent policy that prevents arbitrary
  privileged pods from accessing the TPM device.
- Keep OpenBao nodes isolated from general tenant workloads.

### T6: Compromised Running Node

Scenario: An attacker gains root on an enrolled node while OpenBao or the plugin
can ask the TPM to unseal `K`.

Expected claim:

- TPM sealing does not protect against an attacker who can invoke the unseal
  operation under valid boot and policy conditions.

Mitigations:

- Do not claim runtime compromise resistance.
- Reduce exposure of `K` in process memory where practical.
- Use Secure Boot or measured policies to prevent some offline boot tampering.
- Harden the host, service account, and plugin process.
- Prefer a broker that can revoke node authorization if runtime compromise is a
  primary concern.

### T7: PCR Drift and Update Lockout

Scenario: Firmware, Secure Boot database, kernel, initramfs, bootloader, or
plugin changes alter PCR values, making a sealed key unavailable.

Expected claim:

- Stronger measured policies improve tamper resistance but increase lockout
  risk.

Mitigations:

- Start with `tpm-only` and `secureboot` modes only.
- Treat strict measured boot as a future mode requiring policy update tooling.
- Provide a preflight command that checks whether the next boot policy can still
  unseal.
- Require escrow recovery before any policy update.
- Support multiple authorized policy digests during planned updates.

### T8: Enrollment Impersonation

Scenario: An attacker submits an enrollment request for an unapproved node and
receives `K`.

Expected claim:

- Plain enrollment requests are dangerous unless bound to identity, policy, and
  operator approval.

Mitigations:

- Include TPM or platform identity evidence in enrollment requests.
- Include PCR quote or attestation evidence when available.
- Make enrollment grants short lived and single use.
- Bind grants to cluster ID, key ID, node ID, policy mode, and request
  fingerprint.
- Allow single-operator enrollment in the default profile, but support optional
  operator quorum or recovery share threshold controls for higher assurance
  profiles.
- Log all enrollment events.

### T9: Recovery Escrow Failure

Scenario: All enrolled TPM/vTPM copies are lost and operators cannot reconstruct
`K`.

Expected claim:

- Data is permanently unrecoverable without escrow.

Mitigations:

- Make recovery escrow mandatory for `create-key`.
- Separate OpenBao recovery keys from TPM KMS recovery shares in naming and
  documentation.
- Test recovery during deployment acceptance.
- Provide `recover-enroll` rather than defaulting to raw key export.
- Record recovery package fingerprint in local state and operator docs.

### T10: Rotation Bricks Unseal

Scenario: Key rotation updates current key metadata or OpenBao seal blobs in an
unsafe order, leaving nodes unable to decrypt current or historical blobs.

Expected claim:

- Rotation is a high consequence protocol, not a simple local file rewrite.

Mitigations:

- Support a keyring of current and historical decrypt keys.
- Stage rotation: create `K2`, escrow `K2`, enroll all nodes, verify unseal,
  switch current key, rewrap, then retire old keys later.
- Never delete old key material until backups and old seal blobs are outside the
  recovery window.
- Make interrupted rotation resumable and auditable.
- Include downgrade and rollback behavior in tests.

### T11: Revocation Without Rotation

Scenario: Operators want to revoke a previously enrolled node without rotating
the cluster wrapping key `K`.

Expected claim:

- If a node has a local TPM sealed copy of `K`, revocation without rotating `K`
  is not a cryptographic guarantee. The node can continue to unseal as long as
  it still has its sealed object, matching TPM or vTPM state, and valid policy
  conditions.
- If a broker releases key material at each startup and the node does not keep
  a durable local copy of `K`, broker-side revocation can prevent future
  unseals without rotating `K`.
- Neither model can claw back `K` from a currently running compromised process
  or from a node that already extracted and stored the raw key.

Mitigations:

- Treat revocation in local TPM mode as an administrative control unless paired
  with wrapping-key rotation.
- Prefer brokered release for deployments that require node revocation without
  rotating `K`.
- Use short-lived broker grants and bind them to attestation evidence, node
  identity, cluster ID, key ID, and policy version.
- For strong revocation after suspected compromise, rotate `K`, rewrap OpenBao
  seal material, enroll only approved nodes, and retire the old key after the
  recovery window.
- Document three revocation levels: stop future enrollment, stop future broker
  release, and cryptographic revocation through key rotation.

### T12: Plugin Binary Replacement

Scenario: An attacker replaces the KMS plugin binary or lifecycle tooling.

Expected claim:

- OpenBao plugin registration verifies configured checksums, but deployment
  tooling and local file permissions still matter.

Mitigations:

- Require `sha256sum` in OpenBao plugin configuration.
- Sign release artifacts and OCI images.
- Keep plugin directory writable only by trusted deployment automation.
- Include binary identity in measured mode only after update policy tooling
  exists.
- Log plugin version and build metadata in `status`.

### T13: Secret Disclosure Through Logs or CLI Output

Scenario: `K`, recovery material, enrollment grants, or decrypted OpenBao seal
material are printed, logged, written to shell history, or captured in crash
dumps.

Expected claim:

- Lifecycle tooling is part of the sensitive path and must be designed like key
  management tooling.

Mitigations:

- Redact secrets by default.
- Require explicit dangerous flags for raw key export.
- Prefer writing recovery shares directly to separate output files or hardware
  tokens.
- Avoid environment variables for secret transport.
- Keep command output fingerprints and statuses, not key bytes.

### T14: Broker Compromise or Outage

Scenario: The attested unseal broker is unavailable, misconfigured, or
compromised.

Expected claim:

- Brokered mode improves central policy and revocation but introduces an
  internal runtime dependency.
- A compromised broker can become equivalent to a compromised KMS unless key
  release is constrained by policy, audit, and optionally quorum.

Mitigations:

- Keep the broker on a trusted internal network.
- Support HA broker deployment and clear startup failure behavior.
- Store broker key material in an HSM, TPM, sealed local state, or recovery
  protected backend depending on deployment profile.
- Use mTLS, request signing, nonce-based challenges, and replay protection.
- Audit every key release decision.
- Support policy that can require operator approval or quorum for sensitive
  operations while allowing single-operator enrollment in the default profile.
- Consider a local TPM cache profile for sites that cannot tolerate broker
  outages during common restarts.

### T15: Attestation Replay or Confused Identity

Scenario: An attacker replays old attestation evidence or causes the broker to
authorize the wrong node, VM, or workload identity.

Expected claim:

- Attestation evidence must be freshness-bound and tied to the intended
  deployment identity. A valid quote alone is not enough.

Mitigations:

- Use broker-issued nonces or challenges.
- Bind policy to platform identity, workload identity, cluster ID, key ID,
  measurement policy, and enrollment record.
- Expire enrollment requests and broker grants quickly.
- Record attestation evidence fingerprints for audit and anomaly detection.
- Keep platform-specific verifier logic explicit instead of normalizing all
  platforms into one opaque "trusted" boolean.

## Security Modes

### `tpm-only`

Seals `K` to the TPM without PCR policy.

Use when:

- the operator needs minimal friction;
- the primary threat is copied storage or copied state files;
- boot integrity binding is not required.

Limitations:

- Does not detect boot tampering.
- Does not resist a compromised OS that can use the TPM.
- For vTPM, depends heavily on platform controls.

### `secureboot`

Seals `K` to TPM plus Secure Boot related PCR policy.

Use when:

- Secure Boot is consistently enabled and managed;
- the operator can handle firmware and Secure Boot database update procedures;
- the goal is to block simple offline boot tampering.

Limitations:

- Can lock out after firmware or Secure Boot policy changes.
- Does not by itself identify a specific OpenBao plugin binary.

### `measured`

Seals `K` to stricter boot chain, kernel, initramfs, or application
measurements.

Use when:

- the environment has mature measured boot operations;
- policy updates can be staged safely;
- attestation evidence can be verified externally.

Limitations:

- High operational fragility.
- Not suitable for v1 unless policy update and recovery workflows are ready.

## Product Direction Options

### Option A: TPM-only plugin

Runtime:

- local TPM or vTPM only;
- no network dependency during OpenBao startup.

Best fit:

- bare metal;
- edge;
- appliance;
- controlled VM estates.

Risks:

- weaker story for Kubernetes and ordinary vTPM;
- recovery and rotation must be excellent;
- easy to oversell as HSM-like when it is not.

### Option B: Attestation backed unseal broker

Runtime:

- OpenBao node presents attestation evidence;
- broker verifies platform and workload identity;
- broker releases wrapping key material or an encrypted key grant.
- all broker communication stays on an internal or trusted network.

Best fit:

- VMs;
- Kubernetes;
- confidential VM and confidential container deployments;
- environments where node replacement and central revocation matter.

Risks:

- adds a runtime network dependency;
- broker must be highly available;
- starts to resemble a small on-prem KMS or transit service.
- needs platform-specific attestation verifiers rather than a single generic
  vTPM claim.

### Option C: Hybrid TPM cache plus broker/quorum lifecycle

Runtime:

- local TPM unseal after enrollment;
- no broker call during normal restart.

Lifecycle:

- broker, quorum, or recovery custodians approve enrollment, recovery, and
  rotation.

Best fit:

- sites that cannot tolerate a startup network dependency but can tolerate
  lifecycle ceremonies.

Risks:

- more moving pieces than TPM-only;
- product messaging must clearly separate runtime and lifecycle dependencies.

## Recommendation

Do not make ordinary vTPM or Kubernetes host TPM access the primary security
story for this project.

The stronger direction is:

1. Define the project around attested Auto Unseal, not only TPM.
2. Treat local TPM as one backend for a runtime-local profile.
3. Treat an internal-network attestation backed broker as the primary VM and
   Kubernetes architecture.
4. Support recovery enrollment onto new TPMs or attested identities before
   supporting raw export of `K`.
5. Allow single-operator enrollment in the default profile, but design the
   protocol so quorum approval can be enabled later.
6. If a TPM-only plugin is built first, scope it explicitly to physical,
   appliance, edge, and controlled VM environments.

Suggested naming implications:

- `openbao-attested-unseal` is the project name and umbrella.
- `openbao-plugin-kms-attested-unseal` is an appropriate OpenBao KMS plugin
  binary name.
- `openbao-attested-unseal-broker` is an appropriate broker binary name.
- A TPM-only backend can live under the project as a local TPM profile rather
  than defining the project identity.

## Initial MVP Gate

An attested unseal MVP should not proceed unless these are designed before code:

- broker trust model, HA expectations, and internal-network deployment profile;
- platform verifier boundaries for at least one first-class target;
- node identity, workload identity, and attestation evidence formats;
- broker grant format, freshness, and replay protection;
- escrow package format and custody model;
- enrollment request and grant format;
- local state format with multi-key decrypt support;
- rotation protocol and rollback behavior;
- revocation levels and the exact guarantee of each level;
- Kubernetes and vTPM documentation that limits security claims;
- `swtpm` based integration tests;
- one OpenBao Auto Unseal e2e test;
- failure-mode tests for missing TPM, wrong PCRs, wrong key ID, interrupted
  rotation, lost local state, broker outage, and attestation replay.

## Answered Design Questions

- Is a runtime network dependency categorically unacceptable, or only
  undesirable during common node restarts?
  - Answer: acceptable if it stays on an internal or trusted network. External
    network dependency is out of scope for the primary design.
- Is the primary target controlled VM estates, mainstream Kubernetes, edge
  appliances, or all three?
  - Answer: all three.
- Which platform administrators are inside the trusted computing base?
  - Answer: unknown for an open source project. Each deployment profile must
    state its own trusted computing base.
- Can enrollment require quorum approval, or must a single operator be able to
  add a node?
  - Answer: preferably single-operator for the default path, with the protocol
    leaving room for optional quorum controls.
- Should recovery shares allow raw export of `K`, or only recovery enrollment
  onto new TPMs?
  - Answer: prefer recovery enrollment. Raw export, if supported, should be an
    explicit dangerous operation.
- Which platforms need first-class attestation support: AWS NitroTPM, Azure
  Trusted Launch, Google Shielded VM, on-prem libvirt/KubeVirt, confidential
  containers, or another target?
  - Answer: first-class support is preferred for the major VM and Kubernetes
    attestation targets.
- Do we want this repository to remain a TPM plugin or become an attested
  unseal project with TPM as one backend?
  - Answer: attested unseal project with TPM as one backend.

## Remaining Open Questions

- Do we need revocation of a previously enrolled node without rotating `K`?
  - Current position: brokered mode can provide future-startup revocation
    without rotating `K` if nodes do not retain durable local copies of `K`.
    Local TPM mode cannot provide cryptographic revocation without rotating
    `K`.
- Which first-class attestation target should be implemented first?
- Should the first MVP include both brokered mode and local TPM mode, or should
  it deliberately prove one mode first?
- Where should the broker store or protect its copy of wrapping key material in
  the no-external-dependency profile?

## References

- OpenBao 2.6 release notes, Auto Unseal plugins:
  https://openbao.org/community/release-notes/2-6-0/
- OpenBao seal configuration and KMS plugin registration:
  https://openbao.org/docs/configuration/seal/
- OpenBao declarative plugin configuration:
  https://openbao.org/docs/configuration/plugins/
- `go-kms-wrapping` wrapper interface:
  https://github.com/openbao/go-kms-wrapping/blob/main/wrapper.go
- Kubernetes device plugin framework:
  https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/
- AWS NitroTPM:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm.html
- Google Cloud Shielded VM:
  https://cloud.google.com/security/shielded-cloud/shielded-vm
- Azure Trusted Launch:
  https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch
- libvirt domain format, including persistent VM state and TPM device
  configuration:
  https://libvirt.org/formatdomain.html
