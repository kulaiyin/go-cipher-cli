package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/param"
)

type standardParams struct {
	Mode     param.Field
	Input    param.Field
	Password param.Field
	Suffix   param.Field
	Output   param.Field

	// afterStandardize is called after standardize() (normalize + validate + defaults)
	// but before promptInteractive(). Use for cross-field default inference,
	// text cleanup, or mode-dependent preprocessing that Field declarations
	// cannot express.
	afterStandardize func(p *standardParams) error
}

var standardCmd = &cobra.Command{
	Use:          "standard",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := stdParams.standardize(); err != nil {
			return err
		}
		// Hook: mode-dependent preprocessing that Field declarations can't express
		// (cross-field defaults, text cleanup, mode-dependent visibility overrides).
		if stdParams.afterStandardize != nil {
			if err := stdParams.afterStandardize(&stdParams); err != nil {
				return err
			}
		}
		if err := stdParams.promptInteractive(); err != nil {
			return err
		}
		// This is a placeholder command: business logic lives in a run<Cmd>
		// function (see key_derive.go / mntemp.go for the reference pattern).
		return nil
	},
}

func (p *standardParams) standardize() error {
	p.Mode.Type = strings.ToLower(strings.TrimSpace(p.Mode.Type))
	if err := p.validate(); err != nil {
		return err
	}
	p.defaultOutput()
	return nil
}

type fieldEntry struct {
	field    *param.Field
	target   *string
	flagName string
}

func (p *standardParams) fieldEntries() []fieldEntry {
	return []fieldEntry{
		{&p.Mode, &p.Mode.Type, "mode"},
		{&p.Input, &p.Input.Value, "input"},
		{&p.Password, &p.Password.Value, "password"},
		{&p.Suffix, &p.Suffix.Value, "suffix"},
		{&p.Output, &p.Output.Value, "output"},
	}
}

// values returns a snapshot of current parameter values, keyed by flag name.
// Used by Field.Visible predicates to decide per-field visibility.
func (p *standardParams) values() param.FieldValues {
	return param.FieldValues{
		"mode":     p.Mode.Value,
		"input":    p.Input.Value,
		"password": p.Password.Value,
		"suffix":   p.Suffix.Value,
		"output":   p.Output.Value,
	}
}

// validateFields runs each entry's Field.Validate, honoring Visible predicates,
// against the given values snapshot. Shared by all declarative commands.
func validateFields(entries []fieldEntry, vals param.FieldValues) error {
	for _, e := range entries {
		if e.field.Visible != nil && !e.field.Visible(vals) {
			continue
		}
		if err := e.field.Validate(*e.target, e.flagName, vals); err != nil {
			return err
		}
	}
	return nil
}

func (p *standardParams) validate() error {
	return validateFields(p.fieldEntries(), p.values())
}

func (p *standardParams) promptInteractive() error {
	if !param.IsStdinTerminal() {
		return nil
	}
	for _, e := range p.fieldEntries() {
		// Rebuild values each iteration: a previous prompt may have
		// changed a value that affects visibility of later fields.
		vals := p.values()
		if e.field.Visible != nil && !e.field.Visible(vals) {
			continue
		}
		if !e.field.Interactive {
			continue
		}
		if *e.target != "" {
			continue
		}
		if err := e.field.Prompt(e.target, e.flagName); err != nil {
			return err
		}
	}
	return nil
}

func (p *standardParams) defaultOutput() {
	if p.Output.Value == "" {
		p.Output.Value = "output.bin"
	}
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		standardCmd.Short = i18n.T("standard.short")
		standardCmd.Long = i18n.T("standard.long")
	})

	stdParams.Mode.Allowed = []string{"encrypt", "decrypt"}
	stdParams.Mode.Interactive = true
	stdParams.Mode.PromptType = param.PromptSelect
	stdParams.Input.Required = true
	stdParams.Input.Interactive = true
	stdParams.Input.PromptType = param.PromptInput
	stdParams.Password.Required = true
	stdParams.Password.Interactive = true
	stdParams.Password.PromptType = param.PromptPassword
	stdParams.Password.ErrorPrompt = i18n.T("standard.error.password")
	stdParams.Password.Rules = []param.Rule{
		{"min_length", []string{"8"}},
		{"has_letter_digit_special", nil},
	}

	standardCmd.Flags().StringVar(&stdParams.Mode.Type, "mode", "", i18n.T("standard.flag.mode"))
	standardCmd.Flags().StringVarP(&stdParams.Input.Value, "input", "i", "", i18n.T("standard.flag.input"))
	standardCmd.Flags().StringVarP(&stdParams.Password.Value, "password", "p", "", i18n.T("standard.flag.password"))
	standardCmd.Flags().StringVar(&stdParams.Suffix.Value, "suffix", "", i18n.T("standard.flag.suffix"))
	standardCmd.Flags().StringVarP(&stdParams.Output.Value, "output", "o", "", i18n.T("standard.flag.output"))
	rootCmd.AddCommand(standardCmd)
}

var stdParams standardParams
