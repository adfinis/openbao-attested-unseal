# OpenBao Attested Unseal

`openbao-attested-unseal` is an early-stage project for OpenBao Auto Unseal
using attested node or workload identity, with TPM as one backend.

The project is currently pre-production. It has the initial protocol, local
keyring crypto, broker skeleton, and operator lifecycle CLI, while real TPM and
Kubernetes attestation providers are still under development.

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

This repository is not ready for production use. Runtime TPM/Kubernetes
attestation verification, production broker policy, rotation, and platform
provider hardening are not yet implemented.
