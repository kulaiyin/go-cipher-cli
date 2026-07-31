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
		// This is a placeholder command: the shared lifecycle still validates
		// and prompts, and business logic would live in a run<Cmd> function
		// (see key_derive.go / mntemp.go for the reference pattern).
		return stdSet.run(&stdParams)
	},
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
// stdSet drives the shared declarative lifecycle for the placeholder standard
// command. It exercises the same flow as real commands; the command body would
// be a run<Cmd> function (see key_derive.go / mntemp.go).
var stdSet = paramSet[standardParams]{
	fields: func(p *standardParams) []fieldEntry { return p.fieldEntries() },
	normalize: func(p *standardParams) {
		p.Mode.Type = strings.ToLower(strings.TrimSpace(p.Mode.Type))
	},
	afterStandardize: func(p *standardParams) error {
		if p.Output.Value == "" {
			p.Output.Value = "output.bin"
		}
		return nil
	},
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
