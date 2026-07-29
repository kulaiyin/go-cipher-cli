.DEFAULT_GOAL := setup

.PHONY: setup check test release

# Install git hooks for this repository.
# Run once after cloning.
setup:
	git config core.hooksPath scripts/githooks
	@echo "Git hooks installed (scripts/githooks)."
	@echo "pre-commit and commit-msg will now run automatically on every commit."

# Run the same checks that CI runs.
# Use this before pushing to catch issues early.
check:
	@echo "==> Scanning for CJK characters in Go source..."
	@! grep -rPn '[\x{4e00}-\x{9fff}\x{3000}-\x{303f}\x{ff00}-\x{ffef}]' --include='*.go' cmd/ internal/ main.go 2>/dev/null
	@echo "==> gofmt..."
	@test -z "$$(gofmt -l .)" || (gofmt -d . && exit 1)
	@echo "==> go vet..."
	go vet ./...
	@echo "==> go build..."
	go build ./...
	@echo "==> go test..."
	go test ./...
	@echo ""
	@echo "All checks passed."

# Run the full test suite (including slow argon2 tests).
test:
	@echo "==> go test ./..."
	@go test ./...

# Build release artifacts with goreleaser (local snapshot, no publish).
# Output lands in dist/ — .deb, .tar.gz, checksums, etc.
release:
	goreleaser release --snapshot --clean
