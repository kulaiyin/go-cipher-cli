package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadFormStepsValid(t *testing.T) {
	i18n.MustInit("")
	path := writeConfig(t, `[
		[{"id": "Q01", "content": "First"}, {"id": "Q02", "content": "Second"}],
		[{"id": "Q03", "content": "Third"}]
	]`)
	steps, err := loadFormSteps(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 2 || len(steps[0]) != 2 || len(steps[1]) != 1 {
		t.Fatalf("unexpected steps: %+v", steps)
	}
	if steps[0][1].ID != "Q02" || steps[1][0].Content != "Third" {
		t.Fatalf("unexpected content: %+v", steps)
	}
}

func TestLoadFormStepsErrors(t *testing.T) {
	i18n.MustInit("")
	cases := []struct {
		name    string
		content string
	}{
		{"missing file", ""},
		{"invalid json", `not json`},
		{"empty pool", `[]`},
		{"empty step", `[[{"id":"Q01","content":"x"}], []]`},
		{"missing id", `[[{"content":"x"}]]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.content)
			// For the missing-file case, write the config then remove it.
			if tc.name == "missing file" {
				os.Remove(path)
			}
			if _, err := loadFormSteps(path); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestLoadFormStepsErrorMessageIsTranslated(t *testing.T) {
	i18n.MustInit("")
	i18n.SetLanguage("en")
	path := writeConfig(t, `[]`)
	_, err := loadFormSteps(path)
	if err == nil || !strings.Contains(err.Error(), "Question pool config is empty") {
		t.Fatalf("want localized error, got %v", err)
	}
}

func TestLocalizedConfigPath(t *testing.T) {
	i18n.MustInit("")
	orig := tuiDemoConfig
	defer func() { tuiDemoConfig = orig }()
	tuiDemoConfig = filepath.Join(t.TempDir(), "hint-word-pools_en.json")

	// zh file exists -> zh path is picked.
	zhPath := strings.TrimSuffix(tuiDemoConfig, "_en.json") + "_zh.json"
	if err := os.WriteFile(zhPath, []byte("[]"), 0o644); err != nil {
		t.Fatalf("write zh config: %v", err)
	}

	cases := []struct {
		name string
		lang string
		want string
	}{
		{"default en", "en", tuiDemoConfig},
		{"zh with file", "zh", zhPath},
		{"unknown without file", "fr", tuiDemoConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i18n.SetLanguage(tc.lang)
			if got := localizedConfigPath(); got != tc.want {
				t.Fatalf("want %q, got %q", tc.want, got)
			}
		})
	}
}
