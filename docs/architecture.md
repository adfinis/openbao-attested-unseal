# Architecture

`openbao-attested-unseal` is a modular Go application with four binaries and a
shared set of cryptographic, attestation, policy, and recovery primitives.

## Components

| Component | Responsibility |
| --- | --- |
| OpenBao | Owns encrypted storage and calls the external KMS plugin. |
| `bao-kms-unseal` | Implements the OpenBao wrapper contract and selects broker or local TPM mode. |
| `bao-unseald` | Verifies evidence, evaluates policy, performs brokered wrap and unwrap operations, and records audit events. |
| `bao-unseal-agent` | Collects node evidence without granting the OpenBao pod direct TPM access. |
| `bao-unsealctl` | Performs explicit operator ceremonies and diagnostics. |

## Deployment modes

### Brokered mode

OpenBao sends seal material to `bao-unseald` through the plugin. The broker
verifies request evidence, evaluates policy, uses the active wrapping-key
version, and returns only the wrap or unwrap result. OpenBao nodes do not need a
durable copy of the broker wrapping key.

Brokered mode is the intended direction for Kubernetes and replaceable VM
estates because it permits central revocation and audit. The current
implementation is a functional preview: Kubernetes workload verification and
node-evidence correlation work. The broker issues single-use node-evidence
challenges and verifies raw TPM quotes against a configured node UID, enrolled
attestation key, and optional PCR policy before storing a digest-only verified
projection. Broker key material still uses a development protection profile,
while TPM node AK policy and publisher scope are durable, revisioned broker
state managed by authenticated and audited control-plane operations.

### Local TPM mode

Each approved stable node stores a TPM-sealed copy of the cluster wrapping key.
The plugin opens the TPM, satisfies the configured policy, and performs wrap or
unwrap locally. Runtime operation has no broker dependency.

Local TPM mode has a smaller operational footprint but weaker revocation and
node-replacement semantics. Removing a node does not invalidate copied TPM
state; distrust of a formerly enrolled node requires wrapping-key rotation.

## Runtime planes

The broker exposes four logical planes:

- data: challenge, wrap, unwrap, and readiness;
- evidence: node-evidence challenge, verification, and refresh;
- control: enrollment, revocation, rotation, recovery, and policy;
- diagnostics: sanitized status, audit correlation, and evidence inspection.

These planes currently share one authenticated gRPC endpoint. TPM
node-evidence challenge and publish calls require an mTLS publisher certificate
authorized by the active node enrollment. Node enrollment, listing, and
revocation require the cluster-scoped `node-evidence-admin` role. The remaining
control-plane and diagnostic APIs still need distinct authorization roles
before production use.

## Key lifecycle

Wrapping keys are versioned as pending, active, decrypt-only, or retired. New
wraps use the active version; old blobs remain readable through decrypt-only
versions. OpenBao root-key rotation through `/sys/rotate/root` rewrites the
stored auto-unseal key after a wrapping-key change.

Old-key retirement is intentionally not implemented until the broker can prove
the stored key uses the new version and the operator acknowledges backup
retention consequences.

## Recovery

Recovery packages split the wrapping key into threshold shares. Normal
operations do not export the raw key. Recovery reconstructs access only for an
explicit enrollment ceremony onto a replacement broker or TPM target.

## Current boundaries

The project does not claim protection against a compromised running OpenBao
process, a malicious broker host administrator, or a virtualization platform
that can clone complete vTPM state. See the [threat model](security/threat-model.md)
and provider-specific security profiles for the precise claims.
