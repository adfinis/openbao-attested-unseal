##@ End-To-End Tests

OPENBAO_E2E_IMAGE ?= openbao/openbao:2.6.0-beta20260622
OPENBAO_E2E_ALPINE_IMAGE ?= alpine:3.20
E2E_TEST_FLAGS ?= -count=1 -v

.PHONY: test-e2e
test-e2e: ## Run Docker-backed OpenBao E2E tests.
	@OPENBAO_E2E_IMAGE="$(OPENBAO_E2E_IMAGE)" \
		OPENBAO_E2E_ALPINE_IMAGE="$(OPENBAO_E2E_ALPINE_IMAGE)" \
		"$(GO)" test -tags=e2e $(E2E_TEST_FLAGS) ./test/e2e/...
