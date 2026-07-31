package param

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"

	"go-cipher-cli/internal/i18n"
)

// Output prints a line of text to the terminal's standard output.
func Output(message string) {
	fmt.Fprintln(os.Stdout, message)
}

// Confirm prompts a yes/no question and returns the user's choice.
func Confirm(message string) (bool, error) {
	confirm := &survey.Confirm{Message: message}
	var ok bool
	if err := survey.AskOne(confirm, &ok); err != nil {
		return false, err
	}
	return ok, nil
}

// Select prompts the user to choose one of the given options and returns the
// chosen option. defaultLabel, when non-empty, is pre-selected; the user
// accepts it by pressing Enter. help, when non-empty, is shown as a hint under
// the prompt.
func Select(message string, options []string, defaultLabel string, help string) (string, error) {
	p := &survey.Select{Message: message, Options: options, Default: defaultLabel, Help: help}
	var chosen string
	if err := survey.AskOne(p, &chosen, survey.WithValidator(i18nRequired())); err != nil {
		return "", err
	}
	return chosen, nil
}

// Input prompts the user for a single line of text and returns the input.
// defaultValue, when non-empty, is prefilled; the user accepts it by pressing
// Enter. help, when non-empty, is shown as a hint under the prompt.
func Input(message string, defaultValue string, help string) (string, error) {
	p := &survey.Input{Message: message, Default: defaultValue, Help: help}
	var input string
	if err := survey.AskOne(p, &input, survey.WithValidator(i18nRequired())); err != nil {
		return "", err
	}
	return input, nil
}

// Password prompts the user for a hidden password and returns it.
func Password(message string) (string, error) {
	p := &survey.Password{Message: message}
	var pw string
	if err := survey.AskOne(p, &pw, survey.WithValidator(i18nRequired())); err != nil {
		return "", err
	}
	return pw, nil
}

// MultiInput prompts the user for multiple lines of text and returns the
// combined input. help, when non-empty, is shown as a hint under the prompt.
func MultiInput(message string, help string) (string, error) {
	p := &survey.Multiline{Message: message, Help: help}
	var input string
	if err := survey.AskOne(p, &input, survey.WithValidator(i18nRequired())); err != nil {
		return "", err
	}
	return input, nil
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
