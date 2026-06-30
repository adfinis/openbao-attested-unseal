##@ Build And Release

.PHONY: build
build: ## Build all command binaries with version metadata.
	@mkdir -p bin
	@"$(GO)" build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o "bin/$(PLUGIN_BINARY_NAME)" ./cmd/bao-kms-unseal
	@"$(GO)" build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o "bin/$(BROKER_BINARY_NAME)" ./cmd/bao-unseald
	@"$(GO)" build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o "bin/$(CTL_BINARY_NAME)" ./cmd/bao-unsealctl
	@"$(GO)" build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o "bin/$(AGENT_BINARY_NAME)" ./cmd/bao-unseal-agent

.PHONY: release-artifacts
release-artifacts: clean-dist ## Build Linux release binaries and checksums.
	@set -eu; \
	mkdir -p "$(DIST_DIR)"; \
	for target in $(RELEASE_TARGETS); do \
		goos="$${target%/*}"; \
		goarch="$${target#*/}"; \
		for cmd in bao-kms-unseal bao-unseald bao-unsealctl bao-unseal-agent; do \
			artifact="$(DIST_DIR)/$${cmd}_$(VERSION)_$${goos}_$${goarch}"; \
			printf 'building %s\n' "$$artifact"; \
			CGO_ENABLED=0 GOOS="$$goos" GOARCH="$$goarch" "$(GO)" build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o "$$artifact" "./cmd/$${cmd}"; \
		done; \
	done
	@$(MAKE) checksums

.PHONY: checksums
checksums: ## Generate release artifact checksums.
	@set -eu; \
	artifacts="$$(find "$(DIST_DIR)" -maxdepth 1 -type f ! -name "$$(basename "$(CHECKSUM_FILE)")" -exec basename {} \; | sort)"; \
	if [ -z "$$artifacts" ]; then \
		printf '%s\n' 'No release artifacts found for checksum generation.'; \
		exit 1; \
	fi; \
	cd "$(DIST_DIR)" && $(CHECKSUM) $$artifacts > "$$(basename "$(CHECKSUM_FILE)")"

.PHONY: clean-dist
clean-dist: ## Remove release artifacts.
	@rm -rf "$(DIST_DIR)"
