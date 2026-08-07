package param

import (
	"errors"
	"fmt"

	"github.com/charmbracelet/huh"

	"go-cipher-cli/internal/i18n"
)

// Confirm prompts a yes/no question and returns the user's choice. defaultValue
// is pre-selected; the user accepts it by pressing Enter.
func Confirm(message string, defaultValue bool) (bool, error) {
	ok := defaultValue
	err := runForm(huh.NewConfirm().Title(message).Value(&ok))
	if err != nil {
		return false, translateAbort(err)
	}
	return ok, nil
}

// Select prompts the user to choose one of the given options and returns the
// chosen option. defaultLabel, when non-empty, is pre-selected; the user
// accepts it by pressing Enter. help, when non-empty, is shown as a hint under
// the prompt.
func Select(message string, options []string, defaultLabel string, help string) (string, error) {
	field := huh.NewSelect[string]().
		Title(message).
		Options(huh.NewOptions(options...)...)
	if help != "" {
		field = field.Description(help)
	}
	chosen := defaultLabel
	if err := runForm(field.Value(&chosen)); err != nil {
		return "", translateAbort(err)
	}
	return chosen, nil
}

// PromptOption customizes an interactive prompt.
type PromptOption func(*promptOptions)

type promptOptions struct {
	required   bool
	validators []func(string) error
}

// WithoutRequired disables the default non-empty validation.
func WithoutRequired() PromptOption {
	return func(o *promptOptions) { o.required = false }
}

// WithValidator appends a validation function run after the non-empty check.
func WithValidator(fn func(string) error) PromptOption {
	return func(o *promptOptions) { o.validators = append(o.validators, fn) }
}

func applyOptions(opts []PromptOption) *promptOptions {
	o := &promptOptions{required: true}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// validator returns the combined validation function for the field, or nil when
// no validation is configured. The non-empty check runs first when enabled.
func (o *promptOptions) validator() func(string) error {
	validators := o.validators
	if o.required {
		validators = append([]func(string) error{i18nRequired}, validators...)
	}
	if len(validators) == 0 {
		return nil
	}
	return func(s string) error {
		for _, v := range validators {
			if err := v(s); err != nil {
				return err
			}
		}
		return nil
	}
}

// Input prompts the user for a single line of text and returns the input.
// defaultValue, when non-empty, is prefilled; the user accepts it by pressing
// Enter. help, when non-empty, is shown as a hint under the prompt.
func Input(message string, defaultValue string, help string, opts ...PromptOption) (string, error) {
	o := applyOptions(opts)
	field := huh.NewInput().Title(message).Value(&defaultValue)
	if help != "" {
		field = field.Description(help)
	}
	if v := o.validator(); v != nil {
		field = field.Validate(v)
	}
	if err := runForm(field); err != nil {
		return "", translateAbort(err)
	}
	return defaultValue, nil
}

// Password prompts the user for a hidden password and returns it as UTF-8
// bytes so callers can wipe it after use. help, when non-empty, is shown as a
// hint under the prompt. (The underlying huh textinput still buffers a string;
// this returns a byte copy the caller owns.)
func Password(message string, help string, opts ...PromptOption) ([]byte, error) {
	o := applyOptions(opts)
	var pw string
	field := huh.NewInput().Title(message).EchoMode(huh.EchoModePassword).Value(&pw)
	if help != "" {
		field = field.Description(help)
	}
	if v := o.validator(); v != nil {
		field = field.Validate(v)
	}
	if err := runForm(field); err != nil {
		return nil, translateAbort(err)
	}
	return []byte(pw), nil
}

// MultiInput prompts the user for multiple lines of text and returns the
// combined input. help, when non-empty, is shown as a hint under the prompt.
func MultiInput(message string, help string, opts ...PromptOption) (string, error) {
	o := applyOptions(opts)
	var input string
	field := huh.NewText().Title(message).Value(&input)
	if help != "" {
		field = field.Description(help)
	}
	if v := o.validator(); v != nil {
		field = field.Validate(v)
	}
	if err := runForm(field); err != nil {
		return "", translateAbort(err)
	}
	return input, nil
}

// i18nRequired rejects empty input with a localized message.
func i18nRequired(s string) error {
	if s == "" {
		return fmt.Errorf("%s", i18n.T("common.error.required"))
	}
	return nil
}

// runForm runs a single-field huh form. The built-in help bar is suppressed
// because its keybinding hints are hardcoded English; localized help text is
// rendered instead via Description.
func runForm(field huh.Field) error {
	return huh.NewForm(huh.NewGroup(field)).WithShowHelp(false).Run()
}

// translateAbort maps huh's user-abort sentinel to a localized message so a
// Ctrl+C during an interactive prompt does not leak English text.
func translateAbort(err error) error {
	if errors.Is(err, huh.ErrUserAborted) {
		return fmt.Errorf("%s", i18n.T("common.error.aborted"))
	}
	return err
}
