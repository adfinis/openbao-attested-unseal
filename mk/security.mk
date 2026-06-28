##@ Security

.PHONY: vulncheck
vulncheck: ## Run govulncheck when installed.
	@if command -v "$(GOVULNCHECK)" >/dev/null 2>&1; then "$(GOVULNCHECK)" ./...; else printf '%s\n' 'govulncheck not installed; skipping govulncheck.'; fi

.PHONY: go-licenses
go-licenses:
	@if ! command -v "$(GO_LICENSES)" >/dev/null 2>&1; then \
		printf '%s\n' 'go-licenses not installed; run make install-go-tools.'; \
		exit 1; \
	fi

.PHONY: license-check
license-check: go-licenses ## Verify shipped Go dependency licenses.
	@"$(GO_LICENSES)" check \
		--allowed_licenses="$(GO_LICENSES_ALLOWED_CSV)" \
		--ignore "$(GO_LICENSES_IGNORE)" \
		$(GO_LICENSES_PACKAGE_TARGETS)

.PHONY: license-report
license-report: go-licenses ## Generate dependency license report.
	@mkdir -p "$(LICENSE_REPORT_DIR)"
	@"$(GO_LICENSES)" report \
		--ignore "$(GO_LICENSES_IGNORE)" \
		$(GO_LICENSES_PACKAGE_TARGETS) \
		> "$(LICENSE_REPORT_DIR)/go-licenses-report.csv" \
		2> "$(LICENSE_REPORT_DIR)/go-licenses-report.stderr.log"
	@printf 'License report written to %s\n' "$(LICENSE_REPORT_DIR)/go-licenses-report.csv"

.PHONY: security-ci
security-ci: vulncheck security-scan-fs ## Run vulnerability and filesystem security scans.

.PHONY: security-scan-fs
security-scan-fs: ## Run Trivy filesystem scan when installed.
	@if command -v "$(TRIVY)" >/dev/null 2>&1; then \
		"$(TRIVY)" fs \
			--scanners vuln,misconfig \
			--severity HIGH,CRITICAL \
			--ignore-unfixed \
			--exit-code 1 \
			--ignorefile .trivyignore \
			--skip-version-check \
			--skip-dirs .github/tools/node_modules \
			--skip-dirs bin \
			--skip-dirs dist \
			--skip-dirs public \
			.; \
	else \
		printf '%s\n' 'trivy not installed; skipping filesystem security scan.'; \
	fi

.PHONY: test-ast
test-ast: ## Run ast-grep rule tests.
	@if command -v "$(AST_GREP)" >/dev/null 2>&1; then \
		"$(AST_GREP)" test -c .ast-grep/sgconfig.yml; \
	else \
		printf '%s\n' 'ast-grep not installed; skipping ast-grep rule tests.'; \
	fi

.PHONY: lint-ast
lint-ast: ## Run ast-grep architecture and safety rules.
	@if ! find cmd internal -name '*.go' 2>/dev/null | grep -q .; then \
		printf '%s\n' 'No Go files yet; skipping ast-grep scan.'; \
	elif command -v "$(AST_GREP)" >/dev/null 2>&1; then \
		"$(AST_GREP)" scan -c .ast-grep/sgconfig.yml --report-style=medium --error .; \
	else \
		printf '%s\n' 'ast-grep not installed; skipping ast-grep scan.'; \
	fi

.PHONY: semgrep-rules-test
semgrep-rules-test: ## Run Semgrep rule tests when installed.
	@if command -v "$(SEMGREP)" >/dev/null 2>&1; then \
		"$(SEMGREP)" scan --test --config .semgrep/rules .semgrep/tests; \
	else \
		printf '%s\n' 'Semgrep not installed; skipping Semgrep rule tests.'; \
	fi

.PHONY: semgrep-ci
semgrep-ci: semgrep-rules-test ## Run blocking Semgrep CI scan.
	@targets=""; for d in $(SEMGREP_TARGETS); do [ -e "$$d" ] && targets="$$targets $$d"; done; \
	if [ -z "$$targets" ] || ! find $$targets -name '*.go' 2>/dev/null | grep -q .; then \
		printf '%s\n' 'No Semgrep targets yet; skipping Semgrep CI scan.'; \
	elif command -v "$(SEMGREP)" >/dev/null 2>&1; then \
		mkdir -p "$(SEMGREP_ARTIFACT_DIR)"; \
		"$(SEMGREP)" scan --metrics=off --no-git-ignore --error --json --output "$(SEMGREP_OUTPUT_JSON)" $(SEMGREP_CONFIG_FLAGS) $$targets; \
	else \
		printf '%s\n' 'Semgrep not installed; skipping Semgrep CI scan.'; \
	fi
