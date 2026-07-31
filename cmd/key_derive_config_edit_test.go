package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
)

// TestConfigFilePath verifies the derived config path lands in the mntemp
// default directory with a <name>_<timestamp>.yaml filename.
func TestConfigFilePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	path := configFilePath()
	wantDir := filepath.Join(dir, "mntemp", mntempDefaultName)
	if filepath.Dir(path) != wantDir {
		t.Errorf("config dir = %q, want %q", filepath.Dir(path), wantDir)
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, mntempDefaultName+"_") || !strings.HasSuffix(base, ".yaml") {
		t.Errorf("config filename = %q, want %s_<timestamp>.yaml", base, mntempDefaultName)
	}
}

// TestRecoveryConfigPath checks that the recovery config output shares the
// config file's directory and timestamp base with a .txt extension.
func TestRecoveryConfigPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/tmp/x/mntemp/default/default_20260731_185346.yaml", "/tmp/x/mntemp/default/default_20260731_185346.txt"},
		{"my-config.yaml", "my-config.txt"},
		{"/a/b/c", "/a/b/c.txt"}, // no extension
	}
	for _, tt := range tests {
		if got := recoveryConfigPath(tt.in); got != tt.want {
			t.Errorf("recoveryConfigPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestResolveConfigPath covers the three path behaviours: empty custom ->
// auto-generated under mntemp; missing custom path -> template generated there;
// existing custom path -> edited in place, never overwritten.
func TestResolveConfigPath(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	// 1. No custom path: fresh template under mntemp default dir.
	p1, err := resolveConfigPath("", "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p1) != filepath.Join(os.Getenv("TMPDIR"), "mntemp", mntempDefaultName) {
		t.Errorf("auto path dir = %q", filepath.Dir(p1))
	}
	raw1, _ := os.ReadFile(p1)
	if !strings.Contains(string(raw1), "input:") {
		t.Errorf("auto path did not generate a template:\n%s", raw1)
	}

	// 2. Custom path that does not exist: template generated there (mkdirs).
	custom := filepath.Join(t.TempDir(), "nested", "custom.yaml")
	p2, err := resolveConfigPath(custom, "hint-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if p2 != custom {
		t.Errorf("custom path = %q, want %q", p2, custom)
	}
	raw2, _ := os.ReadFile(custom)
	if !strings.Contains(string(raw2), `hint: "hint-xyz"`) {
		t.Errorf("template hint prefill missing:\n%s", raw2)
	}

	// 3. Existing custom path: left untouched (no template regeneration).
	existing := filepath.Join(t.TempDir(), "keep.yaml")
	orig := "input: \"keep me\"\n"
	if err := os.WriteFile(existing, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	p3, err := resolveConfigPath(existing, "")
	if err != nil {
		t.Fatal(err)
	}
	raw3, _ := os.ReadFile(existing)
	if string(raw3) != orig {
		t.Errorf("existing file was overwritten: %q", raw3)
	}
	if p3 != existing {
		t.Errorf("existing path = %q, want %q", p3, existing)
	}
}

// TestWriteConfigTemplate checks the annotated template: all four fields
// present, strength defaulted to medium, an 8-word diceware example comment,
// optional hint prefill, and 0600 permissions.
func TestWriteConfigTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "recovery.yaml")
	if err := writeConfigTemplate(path, "my hint"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"input:", "hint: \"my hint\"", `strength: "medium"`} {
		if !strings.Contains(s, want) {
			t.Errorf("template missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "password") {
		t.Errorf("template must not contain a password field (kept off disk):\n%s", s)
	}

	// The template must include an 8-word diceware example as a comment.
	exLine := ""
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, i18n.T("key_derive.config_edit.template_input_example")) {
			exLine = line
			break
		}
	}
	if exLine == "" {
		t.Fatalf("no example comment in template:\n%s", s)
	}
	var words []string
	for _, tk := range strings.Fields(exLine) {
		if isLowerAlphaWord(tk) {
			words = append(words, tk)
		}
	}
	if len(words) != 8 {
		t.Errorf("expected 8 lowercase diceware words in example, got %d in %q", len(words), exLine)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("template perms = %o, want 600", info.Mode().Perm())
	}
}

// isLowerAlphaWord reports whether s is a non-empty ASCII lowercase word or
// hyphenated lowercase word (the EFF diceware list is lowercase English words,
// a few of which contain a hyphen, e.g. "felt-tip"). Digits and CJK/punct are
// rejected so the i18n label tokens never count as words.
func isLowerAlphaWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '-' {
			continue
		}
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// TestLoadConfigFile_UnknownField ensures a typo in a field name is rejected
// instead of silently dropping the value.
func TestLoadConfigFile_UnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recovery.yaml")
	bad := "input: \"abc\"\npasword: \"x\"\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(path); err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}

	good := "input: \"abc\"\nstrength: \"basic\"\n"
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := loadConfigFile(path)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if d.Input != "abc" || d.Strength != "basic" {
		t.Errorf("parsed data mismatch: %+v", d)
	}
}

// TestValidateConfigFileData covers requiredness, password rules, and strength
// normalization (empty -> medium; unsupported -> error).
func TestValidateConfigFileData(t *testing.T) {
	valid := configFileData{Input: "ThisIsAFixedProbeInputForGoldenVector2026", Strength: "basic"}
	if err := validateConfigFileData(&valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name string
		data configFileData
	}{
		{"empty input", configFileData{}},
		{"short input", configFileData{Input: "short"}},
		{"bad strength", configFileData{Input: "ThisIsAFixedProbeInputForGoldenVector2026", Strength: "super"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateConfigFileData(&tc.data); err == nil {
				t.Errorf("expected validation error, got nil")
			}
		})
	}

	def := configFileData{Input: "ThisIsAFixedProbeInputForGoldenVector2026"}
	if err := validateConfigFileData(&def); err != nil {
		t.Fatalf("strength-empty config rejected: %v", err)
	}
	if def.Strength != "medium" {
		t.Errorf("empty strength should default to medium, got %q", def.Strength)
	}
}
