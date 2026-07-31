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

// Validate checks value against the field's requiredness, allowed values, and
// rules. values provides the other parameter values so rules can express
// cross-field constraints; pass nil when no other values are available.
func (f *Field) Validate(value string, flagName string, values FieldValues) error {
	if value == "" {
		if f.Required && !f.Interactive {
			return fmt.Errorf("%s", i18n.TWithData("param.error.required", map[string]interface{}{
				"Flag": flagName,
			}))
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

// Prompt runs an interactive survey for the field, collects input into target,
// then validates the result — looping on failure until valid input is received.
func (f *Field) Prompt(target *string, flagName string) error {
	promptMsg := i18n.T(fmt.Sprintf("standard.prompt.%s", flagName))
	for {
		switch f.PromptType {
		case PromptSelect:
			labels := make([]string, len(f.Allowed))
			labelToValue := make(map[string]string, len(f.Allowed))
			for i, a := range f.Allowed {
				key := fmt.Sprintf("standard.option.%s.%s", flagName, a)
				label := i18n.T(key)
				if label == key {
					label = a
				}
				labels[i] = label
				labelToValue[label] = a
			}
			chosen, err := Select(promptMsg, labels)
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
			input, err := MultiInput(promptMsg)
			if err != nil {
				return err
			}
			*target = input
		default:
			input, err := Input(promptMsg)
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
