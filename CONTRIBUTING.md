# Contributing to go-cipher-cli

## Setup

After cloning the repository, install the git hooks:

```bash
make
```

This configures `core.hooksPath` to `scripts/githooks/`, so `pre-commit` and
`commit-msg` checks run automatically on every `git commit`.

You can also run all checks manually before pushing:

```bash
make check
```

## Commit Rules

### 1. Commit messages must be in English

CJK characters (Chinese, Japanese, Korean) are **not allowed** in commit
messages or source code (`.go` files).

### 2. Follow Conventional Commits

Every commit message must follow this format:

```
type(optional-scope): description
```

Supported types:

| Type       | Use for                                      |
| ---------- | -------------------------------------------- |
| `feat`     | New feature                                  |
| `fix`      | Bug fix                                      |
| `docs`     | Documentation changes                        |
| `style`    | Formatting, missing semicolons, etc.         |
| `refactor` | Code restructuring without feature/fix       |
| `perf`     | Performance improvement                      |
| `test`     | Adding or updating tests                     |
| `chore`    | Build process, dependencies, tooling         |
| `ci`       | CI configuration                             |
| `build`    | Build system or external dependencies        |
| `revert`   | Revert a previous commit                     |

Examples:

```
feat: add diceware passphrase generator
fix(crypto): handle empty salt in HKDF expand
docs: update APT installation guide
chore: bump golang.org/x/crypto to v0.54.0
```

### 3. Go source code rules

- **No CJK characters** anywhere in `.go` files (comments, strings, identifiers)
- **gofmt**: all code must be formatted with `gofmt`
- **No trailing whitespace**
- **Files must end with a newline**

## What Gets Checked

### Local hooks (run on every `git commit`)

| Hook          | Checks                                       |
| ------------- | -------------------------------------------- |
| `pre-commit`  | CJK in .go, gofmt, trailing whitespace, EOL  |
| `commit-msg`  | CJK in message, Conventional Commits format  |

### CI (runs on every `git push`)

- `go vet ./...`
- `go test ./...`
- `go build ./...`
- CJK scan & gofmt (same as local hooks)
