##@ Tooling

.PHONY: bootstrap
bootstrap: ## Prepare local development prerequisites.
	@printf 'Go toolchain: %s\n' '$(GO_VERSION)'
	@if command -v npm >/dev/null 2>&1; then \
		npm ci --prefix .github/tools; \
	else \
		printf '%s\n' 'npm not found; skipping ast-grep tool install.'; \
	fi
	@$(MAKE) install-go-tools
	@$(MAKE) install-proto-tools

.PHONY: install-go-tools
install-go-tools: ## Install pinned optional Go quality tools into bin/.
	@mkdir -p "$(GOBIN)"
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)

.PHONY: install-proto-tools
install-proto-tools: ## Install pinned protobuf generation tools into bin/.
	@mkdir -p "$(GOBIN)"
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	@env -u GOFLAGS GOBIN="$(GOBIN)" "$(GO)" install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)
