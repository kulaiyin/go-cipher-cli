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
		if err := stdParams.promptInteractive(); err != nil {
			return err
		}
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

func (p *standardParams) validate() error {
	for _, e := range p.fieldEntries() {
		if err := e.field.Validate(*e.target, e.flagName); err != nil {
			return err
		}
	}
	return nil
}

func (p *standardParams) promptInteractive() error {
	if !param.IsStdinTerminal() {
		return nil
	}
	for _, e := range p.fieldEntries() {
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
