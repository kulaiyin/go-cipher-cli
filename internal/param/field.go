package param

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"go-cipher-cli/internal/i18n"
)

// PromptType enumerates the interactive prompt styles.
type PromptType int

const (
	PromptInput PromptType = iota
	PromptPassword
	PromptSelect
	PromptMultiInput
)

// Rule declares a named validation that a Field must satisfy.
type Rule struct {
	Name string
	Args []string
}

// FieldValues is a snapshot of the current parameter values, keyed by flag name.
// Used by Field.Visible to decide whether a field participates in validation
// and interactive prompting.
type FieldValues map[string]string

// Field is a parameter with type metadata, validation, and interactive prompting.
type Field struct {
	Type        string
	Value       string
	Allowed     []string
	Required    bool
	Interactive bool
	PromptType  PromptType
	Rules       []Rule
	// DefaultValue fills Value when it is empty, applied before validation
	// via ApplyDefault.
	DefaultValue string
	// PromptDefault is the interactive prompt's default: the pre-selected
	// option (PromptSelect) or prefilled text (PromptInput) the user accepts
	// by pressing Enter. It never fills Value itself, so an interactive prompt
	// is still shown even when a default exists. For a non-interactive run,
	// apply the same default explicitly (e.g. in afterStandardize).
	PromptDefault string
	// PromptKeyPrefix namespaces the i18n keys used for prompt messages and
	// option labels, which default to "standard" (standard.prompt.<flag> and
	// standard.option.<flag>.<value>). Commands whose flags collide with the
	// shared namespace set their own prefix (e.g. "key_derive").
	PromptKeyPrefix string
	// RequiredNonInteractive makes the field mandatory even when stdin is not
	// a terminal (no interactive prompt can backfill it). Unlike Required, it
	// does not suppress prompting on a TTY: the field is still prompted when
	// Interactive is set. Use it for fields that are required in batch/CI runs
	// but should not error before an interactive prompt gets a chance.
	RequiredNonInteractive bool
	// PromptHelp shows a help hint under the interactive prompt. The help
	// text is looked up under the prompt message key plus "_help"
	// (e.g. "key_derive.prompt.input_help"); the key must exist in the
	// locales when the field is prompted.
	PromptHelp bool
	// ErrorPrompt, when non-empty, replaces the validation error shown to
	// the user when interactive input fails to satisfy the field's rules.
	ErrorPrompt string
	// Visible is an optional predicate. When non-nil and returning false,
	// the field is skipped during validate() and promptInteractive().
	// Nil means always visible.
	Visible func(values FieldValues) bool
}

// ApplyDefault sets Value to DefaultValue when Value is empty.
func (f *Field) ApplyDefault() {
	if f.Value == "" && f.DefaultValue != "" {
		f.Value = f.DefaultValue
	}
}

// ApplyPromptDefaultNonInteractive fills Value from PromptDefault when stdin is
// not a terminal and the value is still empty. On a TTY the interactive prompt
// would supply the default (via PromptDefault); this mirrors that behaviour for
// batch/CI runs where no prompt is shown.
func (f *Field) ApplyPromptDefaultNonInteractive() {
	if !IsStdinTerminal() && f.Value == "" && f.PromptDefault != "" {
		f.Value = f.PromptDefault
	}
}

// Validate checks value against the field's requiredness, allowed values, and
// rules. values provides the other parameter values so rules can express
// cross-field constraints; pass nil when no other values are available.
func (f *Field) Validate(value string, flagName string, values FieldValues) error {
	if value == "" {
		if f.Required && !f.Interactive {
			return requiredError(flagName)
		}
		// Required fields that are Interactive are exempt here because they
		// are backfilled by promptInteractive() afterwards. A field that must
		// also hold a value in non-interactive (batch) runs opts into
		// RequiredNonInteractive, which errors when no prompt will run.
		if f.RequiredNonInteractive && !IsStdinTerminal() {
			return requiredError(flagName)
		}
		return nil
	}
	if len(f.Allowed) > 0 {
		matched := false
		for _, a := range f.Allowed {
			if value == a {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s", i18n.TWithData("param.error.allowed", map[string]interface{}{
				"Flag": flagName, "Value": value, "Allowed": strings.Join(f.Allowed, ", "),
			}))
		}
	}
	for _, r := range f.Rules {
		fn, ok := ruleRegistry[r.Name]
		if !ok {
			return fmt.Errorf("unknown validation rule %q on --%s", r.Name, flagName)
		}
		if err := fn(r.Args, flagName, values)(value); err != nil {
			return err
		}
	}
	return nil
}

func requiredError(flagName string) error {
	return fmt.Errorf("%s", i18n.TWithData("param.error.required", map[string]interface{}{
		"Flag": flagName,
	}))
}

// promptKeyPrefix returns the i18n key namespace for prompt/option messages.
func (f *Field) promptKeyPrefix() string {
	if f.PromptKeyPrefix != "" {
		return f.PromptKeyPrefix
	}
	return "standard"
}

// promptMessageKey returns the i18n key for the prompt message of a flag.
func (f *Field) promptMessageKey(flagName string) string {
	return fmt.Sprintf("%s.prompt.%s", f.promptKeyPrefix(), flagName)
}

// optionLabelKey returns the i18n key for a select option label.
func (f *Field) optionLabelKey(flagName, value string) string {
	return fmt.Sprintf("%s.option.%s.%s", f.promptKeyPrefix(), flagName, value)
}

// promptHelp returns the i18n help text shown under the prompt, or "" when the
// field does not opt into help.
func (f *Field) promptHelp(flagName string) string {
	if !f.PromptHelp {
		return ""
	}
	return i18n.T(f.promptMessageKey(flagName) + "_help")
}

// defaultOptionLabel maps PromptDefault (a value) to the matching option label,
// or "" when there is no default or no match.
func (f *Field) defaultOptionLabel(labelToValue map[string]string) string {
	if f.PromptDefault == "" {
		return ""
	}
	for label, value := range labelToValue {
		if value == f.PromptDefault {
			return label
		}
	}
	return ""
}

// Prompt runs an interactive survey for the field, collects input into target,
// then validates the result — looping on failure until valid input is received.
func (f *Field) Prompt(target *string, flagName string) error {
	promptMsg := i18n.T(f.promptMessageKey(flagName))
	for {
		switch f.PromptType {
		case PromptSelect:
			labels := make([]string, len(f.Allowed))
			labelToValue := make(map[string]string, len(f.Allowed))
			for i, a := range f.Allowed {
				key := f.optionLabelKey(flagName, a)
				label := i18n.T(key)
				if label == key {
					label = a
				}
				labels[i] = label
				labelToValue[label] = a
			}
			chosen, err := Select(promptMsg, labels, f.defaultOptionLabel(labelToValue), f.promptHelp(flagName))
			if err != nil {
				return err
			}
			*target = labelToValue[chosen]
		case PromptPassword:
			input, err := Password(promptMsg)
			if err != nil {
				return err
			}
			*target = input
		case PromptMultiInput:
			input, err := MultiInput(promptMsg, f.promptHelp(flagName))
			if err != nil {
				return err
			}
			*target = input
		default:
			input, err := Input(promptMsg, f.PromptDefault, f.promptHelp(flagName))
			if err != nil {
				return err
			}
			*target = input
		}
		if err := f.Validate(*target, flagName, nil); err != nil {
			if f.ErrorPrompt != "" {
				fmt.Fprintln(os.Stderr, f.ErrorPrompt)
			} else {
				fmt.Fprintln(os.Stderr, err)
			}
			continue
		}
		return nil
	}
}

func IsStdinTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
