# Changelog

## [0.2.0-preview.1](https://github.com/adfinis/openbao-attested-unseal/compare/0.1.0-preview.1...0.2.0-preview.1) (2026-07-01)


### Features

* **agent:** add continuous node evidence publishing ([6beea93](https://github.com/adfinis/openbao-attested-unseal/commit/6beea93e1c0cc91900781238877fdc5f5d933988))
* **agent:** add standalone node evidence publisher ([7129950](https://github.com/adfinis/openbao-attested-unseal/commit/7129950cb229e9e3b2ceb13bcb0dce40acb8fa4a))
* **broker:** add SQLite-backed unseal broker ([5fdf1b8](https://github.com/adfinis/openbao-attested-unseal/commit/5fdf1b869e7c93748cb3b8047d32d2ac5e5bdc89))
* **broker:** audit node evidence admin operations ([a7bce9d](https://github.com/adfinis/openbao-attested-unseal/commit/a7bce9dec7d93840a7c47795ca58888c5dc49e97))
* **broker:** persist node evidence in SQLite ([aae977d](https://github.com/adfinis/openbao-attested-unseal/commit/aae977df7269146e3f3835d82bcad2df18db2619))
* **contracts:** add protocol and local crypto ([3f9f911](https://github.com/adfinis/openbao-attested-unseal/commit/3f9f911761db08f99d15fd12cf608199000ff153))
* **k8s:** add fake-local node evidence publisher ([1094e27](https://github.com/adfinis/openbao-attested-unseal/commit/1094e27ae0a8505fac3ac5b8d318067cf2db53b3))
* **k8s:** add workload evidence diagnostics ([41e4e81](https://github.com/adfinis/openbao-attested-unseal/commit/41e4e818b49161e94eb1cc0f0df8a3732f1ca70a))
* **kms:** add broker backend and multi-version local keys ([7139324](https://github.com/adfinis/openbao-attested-unseal/commit/7139324b4c5cbcc31f2225ef4ff80a1a73e960be))
* **kubernetes:** add fake node evidence publisher ([78bf290](https://github.com/adfinis/openbao-attested-unseal/commit/78bf290c512bfb616fed3434045548da13c7d1fe))
* **kubernetes:** add node evidence diagnostics ([83725fc](https://github.com/adfinis/openbao-attested-unseal/commit/83725fc74c0e783542d565139e5b51965706a75f))
* **kubernetes:** add node evidence retention pruning ([2e14a8b](https://github.com/adfinis/openbao-attested-unseal/commit/2e14a8b6bd2e68377dd9b635f5d74d14536d633b))
* **kubernetes:** add rbac manifests and kind verification ([6886d65](https://github.com/adfinis/openbao-attested-unseal/commit/6886d65bb72a68f4cbdb3b11949064d85339cf96))
* **kubernetes:** add workload verifier and node evidence policy ([f9ae30f](https://github.com/adfinis/openbao-attested-unseal/commit/f9ae30f7b7bd09d68fcbb76999de7a3ee4c5cf41))
* **kubernetes:** emit workload evidence from plugin ([79c4086](https://github.com/adfinis/openbao-attested-unseal/commit/79c4086ac75d223c7f353270d15043b7bf7d72d6))
* **kubernetes:** wire runtime tokenreview and pod lookup ([eafa0d1](https://github.com/adfinis/openbao-attested-unseal/commit/eafa0d1c26cdb77e1b5d7bac52c37616d7ba0bb6))
* **lifecycle:** add enrollment and recovery flows ([30a4b4c](https://github.com/adfinis/openbao-attested-unseal/commit/30a4b4cd3292b565b2ff15eb225779c73ceffc97))
* **rotation:** add key rotation and revocation workflows ([319d878](https://github.com/adfinis/openbao-attested-unseal/commit/319d878364756f1c173d42cc990e3c3b7b8de929))
* **rotation:** record OpenBao restart verifications ([d9096c9](https://github.com/adfinis/openbao-attested-unseal/commit/d9096c9b224f3ae6b8e8457b9b2d8f5186d8855d))
* **tpm:** add local TPM unseal backend ([1820897](https://github.com/adfinis/openbao-attested-unseal/commit/1820897ad6c4624b66c238f1de369a71ac0142ab))


### Bug Fixes

* **lint:** satisfy ast-grep quality gate ([181a9c6](https://github.com/adfinis/openbao-attested-unseal/commit/181a9c614e816f50134608958ca2890e826f5e0c))

## Changelog

This project uses release-please for release notes once public tags exist.
