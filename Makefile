.DEFAULT_GOAL := setup

.PHONY: setup check test snapshot release

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
	@echo "==> i18n coverage..."
	go run scripts/check-i18n.go
	@echo "==> go test..."
	go test ./...
	@echo ""
	@echo "All checks passed."

# Run the full test suite (including slow argon2 tests).
test:
	@echo "==> go test ./..."
	@go test ./...

# Build a local snapshot (no publish).
# Snapshot mode is NOT tied to a git tag, so the version/timestamps differ
# from a real Release — its checksums cannot be compared with a GitHub
# Release. Use this only for local testing.
snapshot:
	goreleaser release --snapshot --clean

# Reproduce a real CI Release locally (run on a v* tag).
# goreleaser reads the commit timestamp from the tag, so the output can be
# compared against the GitHub Release checksums.
release:
	goreleaser release --clean --skip=publish --timeout 60m
