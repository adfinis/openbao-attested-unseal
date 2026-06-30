# Overview

The project has four planned command surfaces:

| Binary | Role |
|---|---|
| `bao-kms-unseal` | OpenBao KMS plugin entrypoint. |
| `bao-unseald` | Internal-network attested unseal broker daemon. |
| `bao-unsealctl` | Operator lifecycle CLI. |
| `bao-unseal-agent` | Node-local evidence publisher. |

The first architecture task is to decide the MVP shape for brokered mode, local
TPM mode, and recovery enrollment.
