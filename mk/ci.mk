##@ CI

.PHONY: check
check: verify-generated verify-tidy lint security-ci test build ## Run the development quality gate without race or release builds.

.PHONY: ci
ci: ci-core ## Run the full CI-equivalent local gate.

.PHONY: ci-core
ci-core: check test-race release-artifacts ## Run the full core quality gate.
