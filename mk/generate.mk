##@ Code Generation

.PHONY: generate
generate: install-proto-tools ## Generate checked-in protobuf code.
	@"$(BUF)" generate

.PHONY: verify-generated
verify-generated: install-proto-tools ## Verify generated protobuf code is current.
	@set -eu; \
	before="$$(mktemp)"; \
	after="$$(mktemp)"; \
	trap 'rm -f "$$before" "$$after"' EXIT; \
	checksum_generated() { \
		find proto internal/protocol -type f 2>/dev/null | sort | \
			while IFS= read -r file; do shasum -a 256 "$$file"; done; \
	}; \
	checksum_generated > "$$before"; \
	"$(BUF)" generate; \
	checksum_generated > "$$after"; \
	if ! cmp -s "$$before" "$$after"; then \
		diff -u "$$before" "$$after" || true; \
		git diff -- proto internal/protocol; \
		exit 1; \
	fi
