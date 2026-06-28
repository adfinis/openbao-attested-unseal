# OpenBao Attested Unseal

`openbao-attested-unseal` is an early-stage attested Auto Unseal project for
OpenBao. It aims to let OpenBao unwrap seal material from attested node or
workload identity, with TPM as the first backend.

This repository is pre-production. OpenBao KMS plugin support is currently
available in the OpenBao 2.6.0 beta line, and the project has an initial local
TPM mode validated by a Docker and `swtpm` smoke test. Brokered attestation,
Kubernetes workload identity, rotation, revocation, and platform-specific
providers still need production hardening.

## Binaries

| Binary | Purpose |
|---|---|
| `bao-kms-unseal` | OpenBao KMS plugin entrypoint. |
| `bao-unseald` | Internal-network attested unseal broker daemon. |
| `bao-unsealctl` | Operator lifecycle CLI for enrollment, recovery, and diagnostics. |

## Local Checks

```sh
make ci-core
make test-e2e
make build
```

## Status

Do not use this project for production unseal yet. The threat model, recovery
model, and attestation policy are still being narrowed as the implementation
evolves.
