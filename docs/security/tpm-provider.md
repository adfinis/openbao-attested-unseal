# TPM Provider Security Notes

Status: draft

Last reviewed: 2026-06-29

The TPM provider gives the project a local hardware or platform backed root for
some deployment profiles. Its security claim is intentionally narrow:

- the quote binds an enrolled AK to a fresh broker challenge;
- the quote reports selected PCR values from one TPM or vTPM instance;
- local TPM mode can keep the wrapping key sealed to that local TPM state;
- `secureboot` mode can require an enrolled PCR policy, starting with PCR 7 for
  generic PC style Secure Boot evidence.

The TPM provider does not prove that a node is physically secure, that a VM
cannot be cloned, or that a Kubernetes workload is the intended OpenBao pod.
Those claims need platform controls and higher level attestation policy.

## Physical TPM

A physical TPM is a good fit for stable nodes, edge appliances, and hosts where
operators intentionally bind OpenBao unseal capability to specific hardware.
Copying OpenBao storage alone should not be enough to unseal on another host,
because the copied host lacks the TPM sealed key object.

Physical TPM mode still trusts local privileged administrators. A root user that
can alter the OpenBao process, the plugin binary, the boot chain, or the local
state directory can usually affect the unseal path unless measured boot policy
and operational controls are added.

## vTPM

A vTPM is controlled by the virtualization platform. In ordinary VM estates, the
hypervisor or cloud administrator remains inside the trusted computing base. The
project should not claim that a vTPM gives the same protection as a physical TPM
unless the deployment profile also constrains VM cloning, snapshot restore, vTPM
migration, and privileged platform access.

For controlled VM estates, vTPM support can still be valuable. It prevents a
plain storage snapshot from unsealing on an arbitrary VM and gives policy an
attestable node identity. It does not remove the need to trust the platform that
creates, stores, migrates, and restores the vTPM.

## Kubernetes

Local TPM mode is not a natural default for mainstream Kubernetes. Pods are
normally replaceable, while TPM state is node-bound. A pod with broad access to
`/dev/tpmrm0` also increases the node-level trust placed in that workload.

For Kubernetes, the preferred direction is a node or workload attestation agent
that collects TPM or platform evidence and presents constrained evidence to the
OpenBao plugin or broker. The OpenBao pod should not need broad TPM device
access by default.

## PCR 7 Secure Boot Profile

The first `secureboot` profile uses PCR 7 as the generic PC style Secure Boot
anchor. That is useful but platform-specific:

- PCR 7 semantics vary by firmware, VM platform, and Secure Boot
  implementation;
- firmware updates, key enrollment changes, and boot policy changes can change
  PCR 7;
- PCR 7 alone does not prove kernel, initrd, plugin binary, or OpenBao binary
  integrity;
- stricter measured boot profiles need a policy update flow before they are safe
  for production use.

When PCR policy changes are expected, operators should enroll a new policy and
test unseal before retiring the old policy. A bad PCR update can strand a local
TPM sealed key.

## Revocation

Local TPM mode cannot revoke one previously enrolled node without either
removing that node's local sealed object or rotating the cluster wrapping key.
If the node may be compromised or unavailable, key rotation is the reliable
revocation boundary.

Broker mode gives stronger central revocation because policy can deny a subject
before releasing key material. That is one reason broker mode remains the better
default for VM and Kubernetes first deployments that can accept an internal
network dependency.
