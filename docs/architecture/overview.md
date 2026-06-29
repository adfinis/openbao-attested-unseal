# Overview

The project has three planned command surfaces:

| Binary | Role |
|---|---|
| `bao-kms-unseal` | OpenBao KMS plugin entrypoint. |
| `bao-unseald` | Internal-network attested unseal broker daemon. |
| `bao-unsealctl` | Operator lifecycle CLI. |

The first architecture task is to decide the MVP shape for brokered mode, local
TPM mode, and recovery enrollment.
