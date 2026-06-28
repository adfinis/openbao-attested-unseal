---
title: "Local TPM Mode"
description: "Provisioning and runtime configuration for local TPM unseal."
weight: 30
---

# Local TPM Mode

Status: draft

Last reviewed: 2026-06-29

Local TPM mode stores a TPM sealed copy of the cluster wrapping key on each
approved OpenBao node. Runtime unseal does not call a broker or external KMS.
The plugin opens the local TPM, unseals the wrapping key, and uses the local
AEAD keyring format for OpenBao seal blobs.

This mode is intended for stable nodes, edge appliances, and controlled VM
estates where the operator accepts the platform trust boundary described in the
TPM provider security notes.

## Provisioning

Provisioning uses recovery shares. It does not print or write the raw wrapping
key.

```sh
bao-unsealctl tpm provision \
  -state-path /var/lib/openbao-attested-unseal \
  -package recovery.json \
  -shares-file shares.json \
  -policy tpm-only
```

For a simulator or non-default TPM path, pass `-tpm-device`:

```sh
bao-unsealctl tpm provision \
  -state-path ./state \
  -package recovery.json \
  -shares-file shares.json \
  -tpm-device /tmp/bao-swtpm/swtpm.sock
```

For the initial Secure Boot profile:

```sh
bao-unsealctl tpm provision \
  -state-path /var/lib/openbao-attested-unseal \
  -package recovery.json \
  -shares-file shares.json \
  -policy secureboot \
  -pcr-bank sha256 \
  -pcrs 7
```

The command reconstructs the wrapping key in memory from the recovery shares,
seals it into the local TPM, verifies an unseal, and writes only TPM sealed
state.

## Status

```sh
bao-unsealctl tpm status \
  -state-path /var/lib/openbao-attested-unseal \
  -cluster-id prod-eu1 \
  -key-id root \
  -key-version 1
```

Status always reports the local TPM revocation warning:

```text
Warning: local TPM revocation requires key rotation
```

Removing one node's local sealed object is useful cleanup, but it is not a full
revocation boundary if the node or its TPM state may have been copied. Rotate
the cluster wrapping key when a previously enrolled node must be distrusted.

## State Layout

```text
local-tpm/
  keys/
    <key-id>/
      v1.sealed
      v1.metadata.json
      pcr-policy.json
```

State files are expected to be private to the OpenBao or provisioning user. The
loader rejects group or world accessible files and symlinked state paths.

## OpenBao Seal Configuration

OpenBao 2.6.0 beta expects the plugin binary to be registered with
`plugin_directory` and a `plugin "kms"` stanza. The beta configuration uses
`sha256sum` for the plugin checksum:

```hcl
plugin_directory = "/opt/openbao/plugins"

plugin "kms" "attested-unseal" {
  command   = "bao-kms-unseal"
  sha256sum = "<sha256>"
}
```

The generated seal stanza uses the same fields consumed by the plugin wrapper:

```hcl
seal "attested-unseal" {
  mode        = "local-tpm"
  cluster_id  = "prod-eu1"
  key_id      = "root"
  key_version = "1"
  state_path  = "/var/lib/openbao-attested-unseal"
  tpm_device  = "/dev/tpmrm0"
}
```

When testing with `swtpm`, set `tpm_device` to the Unix socket path.

The current Docker smoke path has been verified against
`openbao/openbao:2.6.0-beta20260622` with `swtpm`: initialize with
`-recovery-shares`/`-recovery-threshold`, stop the OpenBao container, start it
again with the same storage, TPM socket, and local TPM state, and confirm
`bao status -format=json` reports `initialized=true` and `sealed=false`.

## Limits

Local TPM mode does not implement remote TPM enrollment. Full remote enrollment
requires a target-specific TPM import or duplicate design and is reserved for a
later milestone.

`secureboot` currently uses PCR 7 for the generic PC style profile. PCR 7 is not
a universal measured boot proof, and firmware or Secure Boot policy changes can
change the expected value.
