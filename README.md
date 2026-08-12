# OpenBao Attested Unseal

`openbao-attested-unseal` is an experimental Auto Unseal implementation for
OpenBao. It supports the OpenBao 2.6 external KMS plugin contract and explores
two deployment profiles:

- brokered unseal, where an internal service authorizes wrap and unwrap
  operations using workload and node evidence;
- local TPM unseal, where approved stable nodes hold TPM-sealed copies of the
  wrapping key and do not require a runtime network service.

The repository is a functional alpha, not a production-ready unseal system.
Local TPM and broker-backed OpenBao restart paths work in test environments,
including multi-version rotation and three-node Raft coverage. Broker key
protection, general control-plane role separation, rotation retirement proof,
and production packaging remain incomplete.

## Components

| Binary | Purpose |
| --- | --- |
| `bao-kms-unseal` | OpenBao external KMS plugin. |
| `bao-unseald` | Internal-network wrap and unwrap broker. |
| `bao-unsealctl` | Bootstrap, recovery, rotation, and diagnostics CLI. |
| `bao-unseal-agent` | Node-local evidence collector and publisher. |

## Development checks

```sh
make check
make test-e2e
```

`make check` is the everyday development gate. Run `make ci-core` once on the
final branch before publication; it adds race tests and cross-compiled release
artifacts. Docker-backed E2E tests remain separate and cover broker mode, local
TPM with `swtpm`, Kubernetes RBAC and kind deployment, and a three-node OpenBao
Raft cluster.

## Documentation

Start with the [documentation index](docs/README.md), then read the
[architecture](docs/architecture.md) and [threat model](docs/security/threat-model.md)
before evaluating deployment profiles.

Do not use this project for production unseal yet.
