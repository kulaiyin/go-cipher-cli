// Package hintpool embeds the question-pool JSON files so the released binary
// is self-contained and does not need a configs/ directory on disk.
package hintpool

import "embed"

// FS exposes the embedded question-pool JSON files, keyed by file name
// (hint-word-pools_en.json / hint-word-pools_zh.json).
//
//go:embed hint-word-pools_en.json hint-word-pools_zh.json
var FS embed.FS
