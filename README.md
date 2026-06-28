# OpenBao Attested Unseal

`openbao-attested-unseal` is an early-stage project for OpenBao Auto Unseal
using attested node or workload identity, with TPM as one backend.

The project is currently design-first. The initial scaffold provides the binary
layout, quality gates, release skeleton, and documentation structure before the
unseal protocol is implemented.

## Binaries

| Binary | Purpose |
|---|---|
| `bao-kms-unseal` | OpenBao `kms` plugin entrypoint. |
| `bao-unseald` | Internal-network attested unseal broker daemon. |
| `bao-unsealctl` | Operator lifecycle CLI for enrollment, recovery, and diagnostics. |

## Build

```sh
make ci-core
make build
bin/bao-kms-unseal version
bin/bao-unseald version
bin/bao-unsealctl version
```

## Documentation

Start with [the threat model](docs/security/threat-model.md). Published
documentation uses the Hugo site scaffold under `website/`.

## Status

This repository is not ready for production use. Runtime unseal behavior,
attestation verification, broker policy, recovery, and rotation are not yet
implemented.
