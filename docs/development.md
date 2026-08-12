# Development and Quality Gates

This project handles unseal and wrapping-key lifecycle paths. Runtime code uses
strict defaults:

- typed configuration and protocol boundaries;
- no broad dynamic Go types;
- no runtime panics;
- propagated contexts and bounded network calls;
- TLS verification enabled outside explicit test modes;
- redacted logs, audit records, and command output;
- mechanically enforced package and adapter boundaries.

Run the core quality gate with:

```sh
make ci-core
```

The gate verifies generated protobuf output, module tidiness, documentation
characters, formatting, ast-grep architecture rules, Semgrep security rules,
Go analysis, vulnerability scanning, unit and race tests, local builds, and
cross-compiled release artifacts. Optional tools are installed with:

```sh
make bootstrap
```

Architecture rules live under `.ast-grep/rules/` and have positive and negative
fixtures under `.ast-grep/tests/`. Error-severity rules fail CI. Warning rules
are used only during a bounded migration and should be promoted to errors when
the corresponding boundary is clean. The complementary Go package-graph test
under `internal/architecture/` prevents forbidden dependency edges even when
imports use aliases or are split across files.

## End-to-end tests

Docker-backed OpenBao tests are intentionally separate:

```sh
make test-e2e
```

The default image tracks the supported OpenBao 2.6 patch line. Override it for
compatibility testing:

```sh
OPENBAO_E2E_IMAGE=openbao/openbao:2.6.1 make test-e2e
```

Set `OPENBAO_E2E_KEEP=1` to preserve temporary Docker resources after a failed
test for debugging.
