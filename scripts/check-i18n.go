// check-i18n verifies that every i18n.T() / i18n.TWithData() call in the
// codebase has a matching key in both locale files, and that no locale key
// is unused. Run it before shipping any user-facing string changes.
//
// Usage: go run scripts/check-i18n.go
//
// Exit code: 0 = clean, 1 = issues found.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

func main() {
	codeKeys := collectCodeKeys()
	enKeys := collectLocaleKeys("internal/i18n/locales/active.en.toml")
	zhKeys := collectLocaleKeys("internal/i18n/locales/active.zh.toml")

	exit := 0

	// Code vs locale
	var missingInEN, missingInZH, unusedInCode []string
	for k := range codeKeys {
		if !enKeys[k] {
			missingInEN = append(missingInEN, k)
		}
		if !zhKeys[k] {
			missingInZH = append(missingInZH, k)
		}
	}
	for k := range enKeys {
		if !codeKeys[k] {
			unusedInCode = append(unusedInCode, k)
		}
	}
	for k := range zhKeys {
		if !codeKeys[k] {
			if !slices.Contains(unusedInCode, k) {
				unusedInCode = append(unusedInCode, k)
			}
		}
	}

	if len(missingInEN) > 0 {
		fmt.Println("❌ Missing in active.en.toml:")
		for _, k := range missingInEN {
			fmt.Println("   ", k)
		}
		exit = 1
	}
	if len(missingInZH) > 0 {
		fmt.Println("❌ Missing in active.zh.toml:")
		for _, k := range missingInZH {
			fmt.Println("   ", k)
		}
		exit = 1
	}
	if len(unusedInCode) > 0 {
		fmt.Println("❌ Defined in locale but unused in code:")
		for _, k := range unusedInCode {
			fmt.Println("   ", k)
		}
		exit = 1
	}

	// EN vs ZH parity
	for k := range enKeys {
		if !zhKeys[k] {
			fmt.Println("❌ EN key missing in ZH:", k)
			exit = 1
		}
	}
	for k := range zhKeys {
		if !enKeys[k] {
			fmt.Println("❌ ZH key missing in EN:", k)
			exit = 1
		}
	}

	if exit == 0 {
		fmt.Printf("✅ i18n coverage: clean (%d code ↔ %d EN ↔ %d ZH)\n",
			len(codeKeys), len(enKeys), len(zhKeys))
	}
	os.Exit(exit)
}

func collectCodeKeys() map[string]bool {
	keys := map[string]bool{}
	re := regexp.MustCompile(`i18n\.(?:T|TWithData)\("([^"]+)"`)

	roots := []string{"cmd", "internal"}
	for _, root := range roots {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, _ := os.ReadFile(path)
			for _, m := range re.FindAllStringSubmatch(string(content), -1) {
				keys[m[1]] = true
			}
			return nil
		})
	}
	return keys
}

func collectLocaleKeys(path string) map[string]bool {
	keys := map[string]bool{}
	content, err := os.ReadFile(path)
	if err != nil {
		return keys
	}
	re := regexp.MustCompile(`(?m)^\[([^\]]+)\]`)
	for _, m := range re.FindAllStringSubmatch(string(content), -1) {
		keys[m[1]] = true
	}
	return keys
}
