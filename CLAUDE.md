# go-cipher-cli

## Common Commands

```bash
go build ./...
go test -count=1 ./...
go run scripts/check-i18n.go     # i18n coverage check
```

## i18n Rules (Mandatory)

**Every user-visible string MUST use `i18n.T()` or `i18n.TWithData()`. Hardcoded English is not allowed.**

### Workflow

1. Write `i18n.T("xxx.xxx.xxx")` in code directly, even if the key doesn't exist yet
2. Add the corresponding key in both `internal/i18n/locales/active.zh.toml` and `active.en.toml`
3. After every user-facing text change, **must confirm both**:
   - `go test -count=1 ./...` — tests pass
   - `go run scripts/check-i18n.go` — coverage clean, no missing/unused keys
4. New keys must be added to EN and ZH simultaneously to keep the key set consistent
