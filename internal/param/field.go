package param

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"golang.org/x/term"

	"go-cipher-cli/internal/i18n"
)

// PromptType enumerates the interactive prompt styles.
type PromptType int

const (
	PromptInput PromptType = iota
	PromptPassword
	PromptSelect
)

// Rule declares a named validation that a Field must satisfy.
type Rule struct {
	Name string
	Args []string
}

// Field is a parameter with type metadata, validation, and interactive prompting.
type Field struct {
	Type        string
	Value       string
	Allowed     []string
	Required    bool
	Interactive bool
	PromptType  PromptType
	Rules       []Rule
}

func (f *Field) Validate(value string, flagName string) error {
	if value == "" {
		if f.Required && !f.Interactive {
			return fmt.Errorf("--%s is required", flagName)
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
			return fmt.Errorf("value %q not allowed, must be one of: %v", value, f.Allowed)
		}
	}
	for _, r := range f.Rules {
		fn, ok := ruleRegistry[r.Name]
		if !ok {
			return fmt.Errorf("unknown validation rule %q on --%s", r.Name, flagName)
		}
		if err := fn(r.Args, flagName)(value); err != nil {
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
			var chosen string
			p := &survey.Select{
				Message: promptMsg,
				Options: labels,
			}
			if err := survey.AskOne(p, &chosen, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
			*target = labelToValue[chosen]
		case PromptPassword:
			p := &survey.Password{
				Message: promptMsg,
			}
			if err := survey.AskOne(p, target, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
		default:
			p := &survey.Input{
				Message: promptMsg,
			}
			if err := survey.AskOne(p, target, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
		}
		if err := f.Validate(*target, flagName); err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		return nil
	}
}

func i18nRequired() survey.Validator {
	return func(val interface{}) error {
		if val == nil {
			return fmt.Errorf("%s", i18n.T("common.error.required"))
		}
		switch v := val.(type) {
		case string:
			if v == "" {
				return fmt.Errorf("%s", i18n.T("common.error.required"))
			}
		case survey.OptionAnswer:
			if v.Value == "" {
				return fmt.Errorf("%s", i18n.T("common.error.required"))
			}
		}
		return nil
	}
}

func IsStdinTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
