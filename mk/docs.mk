##@ Documentation

.PHONY: docs-check
docs-check: ## Check docs for known formatting artifacts and stale names.
	@! grep -R -n --exclude-dir=_archive $$(printf '\357\277\274') README.md docs
	@! grep -R -n --exclude-dir=_archive '⸻' README.md docs
	@! grep -R -n --exclude-dir=_archive 'openbao-kms-tpm' README.md docs
	@! grep -R -n --exclude-dir=_archive '—' README.md docs
