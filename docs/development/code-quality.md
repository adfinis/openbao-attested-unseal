---
title: "Code Quality"
description: "Strict typed Go conventions and local quality gates."
weight: 10
---

# Code Quality

This project handles unseal and wrapping-key lifecycle paths. The codebase
therefore starts with strict defaults:

- no broad dynamic Go types in production code;
- no Viper or environment reads outside configuration boundaries;
- no runtime panics;
- no disabled TLS verification;
- no sensitive log fields;
- typed DTOs at protocol boundaries;
- redacted command output and logs.

Run the local quality gate with:

```sh
make ci-core
```

Docker-backed OpenBao smoke tests are intentionally separate from `ci-core`.
Run them explicitly when validating plugin lifecycle behavior against a real
OpenBao image:

```sh
make test-e2e
```

The default E2E image is the current OpenBao 2.6.0 beta used by the local TPM
smoke test. The local TPM E2E also validates that `/sys/rotate/root` rewrites
OpenBao's stored auto-unseal key through `bao-unsealctl rotate openbao-root`
and that restart auto unseal still works afterward, then records
`bao-unsealctl rotate verify-restart` against `sys/seal-status`. Override the
image when testing another build:

```sh
OPENBAO_E2E_IMAGE=openbao/openbao:2.6.0-beta20260622 make test-e2e
```

Set `OPENBAO_E2E_KEEP=1` to keep temporary Docker resources for debugging a
failed run.
