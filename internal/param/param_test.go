package param

import (
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
)

func TestMain(m *testing.M) {
	i18n.MustInit("en")
	m.Run()
}

// TestValidateRequiredInteractiveSkippedOnEmpty verifies the existing contract:
// a Required+Interactive field does not error on an empty value (the prompt
// backfills it later), regardless of terminal state.
func TestValidateRequiredInteractiveSkippedOnEmpty(t *testing.T) {
	f := Field{Required: true, Interactive: true}
	if err := f.Validate("", "input", nil); err != nil {
		t.Fatalf("Required+Interactive empty value should be allowed (prompt backfills it), got: %v", err)
	}
}

// TestValidateRequiredNonInteractive ensures a field marked
// RequiredNonInteractive errors on empty value in non-interactive runs, which
// is exactly the batch/CI path the flag is meant to guard. On a real TTY the
// prompt would backfill it, so that branch is skipped.
func TestValidateRequiredNonInteractive(t *testing.T) {
	if IsStdinTerminal() {
		t.Skip("stdin is a TTY: non-interactive behaviour cannot be exercised")
	}
	f := Field{Required: true, Interactive: true, RequiredNonInteractive: true}
	if err := f.Validate("", "input", nil); err == nil {
		t.Fatal("RequiredNonInteractive empty value must error in non-interactive runs")
	}
	// With a value it passes like any other field.
	if err := f.Validate("some value", "input", nil); err != nil {
		t.Fatalf("non-empty value should validate, got: %v", err)
	}
}

// TestValidateRequiredFlagOnly keeps the pre-existing behaviour: a Required
// field without Interactive (flag-only) errors when empty.
func TestValidateRequiredFlagOnly(t *testing.T) {
	f := Field{Required: true, Interactive: false}
	if err := f.Validate("", "action", nil); err == nil {
		t.Fatal("Required+!Interactive empty value must error")
	}
}

// TestPromptKeyPrefix verifies the i18n key namespace for prompt messages and
// option labels: "standard" by default, custom prefix when set.
func TestPromptKeyPrefix(t *testing.T) {
	byDefault := &Field{}
	if got := byDefault.promptMessageKey("input"); got != "standard.prompt.input" {
		t.Errorf("default prompt key = %q, want %q", got, "standard.prompt.input")
	}
	if got := byDefault.optionLabelKey("mode", "generate"); got != "standard.option.mode.generate" {
		t.Errorf("default option key = %q, want %q", got, "standard.option.mode.generate")
	}

	custom := &Field{PromptKeyPrefix: "key_derive"}
	if got := custom.promptMessageKey("input"); got != "key_derive.prompt.input" {
		t.Errorf("custom prompt key = %q, want %q", got, "key_derive.prompt.input")
	}
	if got := custom.optionLabelKey("mode", "generate"); got != "key_derive.option.mode.generate" {
		t.Errorf("custom option key = %q, want %q", got, "key_derive.option.mode.generate")
	}
}

// TestDefaultOptionLabel verifies PromptDefault (a value) is mapped back to
// the matching option label for the select prompt.
func TestDefaultOptionLabel(t *testing.T) {
	labelToValue := map[string]string{"generate-label": "generate", "restore-label": "restore"}

	f := &Field{PromptDefault: "generate"}
	if got := f.defaultOptionLabel(labelToValue); got != "generate-label" {
		t.Errorf("default label = %q, want %q", got, "generate-label")
	}

	noDefault := &Field{}
	if got := noDefault.defaultOptionLabel(labelToValue); got != "" {
		t.Errorf("no default should map to empty label, got %q", got)
	}

	noMatch := &Field{PromptDefault: "bogus"}
	if got := noMatch.defaultOptionLabel(labelToValue); got != "" {
		t.Errorf("unmatched default should map to empty label, got %q", got)
	}
}

// TestPromptDefaultDoesNotFillValue confirms PromptDefault never pre-fills the
// Value itself: an interactive prompt must still be shown even when a default
// exists, and non-interactive defaults are applied explicitly by the command.
func TestPromptDefaultDoesNotFillValue(t *testing.T) {
	f := Field{DefaultValue: "recovery-config.txt", PromptDefault: "recovery-config.txt"}
	f.ApplyDefault()
	if f.Value != "recovery-config.txt" {
		t.Errorf("ApplyDefault should fill DefaultValue, got %q", f.Value)
	}
	f2 := Field{PromptDefault: "recovery-config.txt"}
	f2.ApplyDefault()
	if f2.Value != "" {
		t.Errorf("PromptDefault must not fill Value, got %q", f2.Value)
	}
}

// TestApplyPromptDefaultNonInteractive verifies that on a non-terminal stdin
// (batch/CI) the prompt default is applied to the Value, mirroring what the
// interactive prompt would have supplied.
func TestApplyPromptDefaultNonInteractive(t *testing.T) {
	if IsStdinTerminal() {
		t.Skip("stdin is a TTY: non-interactive behaviour cannot be exercised")
	}
	f := Field{PromptDefault: "medium"}
	f.ApplyPromptDefaultNonInteractive()
	if f.Value != "medium" {
		t.Errorf("non-interactive default should fill Value, got %q", f.Value)
	}
	// An explicitly provided value is never overwritten.
	f2 := Field{Value: "advanced", PromptDefault: "medium"}
	f2.ApplyPromptDefaultNonInteractive()
	if f2.Value != "advanced" {
		t.Errorf("explicit value must win over non-interactive default, got %q", f2.Value)
	}
	// No default: untouched.
	f3 := Field{}
	f3.ApplyPromptDefaultNonInteractive()
	if f3.Value != "" {
		t.Errorf("empty PromptDefault must not fill Value, got %q", f3.Value)
	}
}

// TestPromptHelpKey verifies the help lookup: empty when the field does not opt
// in, otherwise the prompt key plus "_help".
func TestPromptHelpKey(t *testing.T) {
	noHelp := &Field{PromptKeyPrefix: "key_derive"}
	if got := noHelp.promptHelp("input"); got != "" {
		t.Errorf("PromptHelp=false should return empty help, got %q", got)
	}
	withHelp := &Field{PromptKeyPrefix: "key_derive", PromptHelp: true}
	if got := withHelp.promptHelp("input"); got == "" {
		t.Error("PromptHelp=true should return the translated help text")
	}
	// The help key is the prompt message key + "_help" (locales define it).
	if got := withHelp.promptMessageKey("input") + "_help"; got != "key_derive.prompt.input_help" {
		t.Errorf("help key = %q, want %q", got, "key_derive.prompt.input_help")
	}
}

// TestRegisterRule verifies command packages can register custom rules and
// that re-registration replaces an existing rule.
func TestRegisterRule(t *testing.T) {
	RegisterRule("test_rule_custom", func(args []string, flagName string, _ FieldValues) func(string) error {
		return func(v string) error {
			if !strings.Contains(v, args[0]) {
				return &errMarker{flag: flagName, want: args[0]}
			}
			return nil
		}
	})
	f := Field{Rules: []Rule{{Name: "test_rule_custom", Args: []string{"x"}}}}
	if err := f.Validate("abc", "input", nil); err == nil {
		t.Fatal("custom rule should reject value missing required substring")
	}
	if err := f.Validate("axc", "input", nil); err != nil {
		t.Fatalf("custom rule should accept matching value, got: %v", err)
	}
}

// errMarker is a small error type used to make TestRegisterRule assertions
// unambiguous without coupling to i18n message text.
type errMarker struct {
	flag string
	want string
}

func (e *errMarker) Error() string {
	return "missing " + e.want + " on --" + e.flag
}
