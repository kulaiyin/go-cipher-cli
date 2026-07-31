package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/validation"
)

// keyDeriveKeyDriveVersion mirrors the frontend KEY_DRIVE_VERSION
// (packages/web/src/constant/const.ts). Stored in recovery configs so a future
// incompatible derivation change can be detected.
const keyDeriveKeyDriveVersion = "1.0.0"

// keyDeriveParams declares the parameters of the key-derive command using the
// declarative standard mode: type metadata, requiredness, validation rules,
// and interactive prompting are expressed as param.Field declarations instead
// of hand-written survey code (see mntemp.go for the reference pattern).
type keyDeriveParams struct {
	Mode     param.Field
	Input    param.Field
	Password param.Field
	Hint     param.Field
	Strength param.Field
	Config   param.Field
	Output   param.Field
	Salt     param.Field

	// afterStandardize is called after standardize() but before
	// promptInteractive(). Used for non-interactive defaults that mirror the
	// interactive prompt defaults (mode/strength), which cannot be expressed
	// as Field declarations because they depend on the resolved mode.
	afterStandardize func(p *keyDeriveParams) error
}

var kdParams keyDeriveParams

var keyDeriveCmd = &cobra.Command{
	Use:          "key-derive --mode <generate|restore> -i <input> -p <password> [flags]",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := kdParams.standardize(); err != nil {
			return err
		}
		if kdParams.afterStandardize != nil {
			if err := kdParams.afterStandardize(&kdParams); err != nil {
				return err
			}
		}
		if err := kdParams.promptInteractive(); err != nil {
			return err
		}
		// All params resolved (flags + interactive): run the command.
		return runKeyDerive(&kdParams)
	},
}

func (p *keyDeriveParams) standardize() error {
	p.Mode.Value = strings.ToLower(strings.TrimSpace(p.Mode.Value))
	if err := p.validate(); err != nil {
		return err
	}
	return nil
}

func (p *keyDeriveParams) fieldEntries() []fieldEntry {
	return []fieldEntry{
		{&p.Mode, &p.Mode.Value, "mode"},
		{&p.Input, &p.Input.Value, "input"},
		{&p.Password, &p.Password.Value, "password"},
		{&p.Hint, &p.Hint.Value, "hint"},
		{&p.Strength, &p.Strength.Value, "strength"},
		{&p.Config, &p.Config.Value, "config"},
		{&p.Output, &p.Output.Value, "output"},
		{&p.Salt, &p.Salt.Value, "salt"},
	}
}

func (p *keyDeriveParams) values() param.FieldValues {
	return param.FieldValues{
		"mode":     p.Mode.Value,
		"input":    p.Input.Value,
		"password": p.Password.Value,
		"hint":     p.Hint.Value,
		"strength": p.Strength.Value,
		"config":   p.Config.Value,
		"output":   p.Output.Value,
		"salt":     p.Salt.Value,
	}
}

func (p *keyDeriveParams) validate() error {
	return validateFields(p.fieldEntries(), p.values())
}

func (p *keyDeriveParams) promptInteractive() error {
	if !param.IsStdinTerminal() {
		return nil
	}
	for _, e := range p.fieldEntries() {
		// Rebuild values each iteration: a previous prompt may have changed a
		// value that affects visibility of later fields (e.g. mode).
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

// runKeyDerive executes the command after all params are resolved (flags +
// interactive): it cleans input/password like the frontend, applies the hint
// default, and dispatches to generate or restore.
func runKeyDerive(p *keyDeriveParams) error {
	// Clean input/password exactly like the frontend (strip whitespace + NFC).
	input := cleanKeyDeriveText(p.Input.Value)
	password := cleanKeyDeriveText(p.Password.Value)

	// Hint defaults to the first 10 chars of the input (frontend behaviour).
	hint := p.Hint.Value
	if hint == "" {
		hint = firstNChars(input, 10)
	}

	strength := kdf.Strength(p.Strength.Value)

	if p.Mode.Value == "restore" {
		return runKeyDeriveRestore(p, input, password, hint, strength)
	}
	return runKeyDeriveGenerate(p, input, password, hint, strength)
}

func init() {
	i18n.MustInit("")
	// Override survey's hardcoded English error prefix ("Sorry, your reply was invalid:")
	// so validation errors are fully multilingual via our i18n translations.
	survey.ErrorTemplate = `{{color .Icon.Format }}{{ .Icon.Text }} {{ .Error.Error }}{{color "reset"}}
`
	// Override the hardcoded "[Enter 2 empty lines to finish]" instruction in the
	// Multiline template so it uses the current language.
	survey.MultilineQuestionTemplate = strings.Replace(
		survey.MultilineQuestionTemplate,
		"[Enter 2 empty lines to finish]",
		i18n.T("key_derive.prompt.multiline_instruction"),
		1,
	)
	refreshCmdDescs = append(refreshCmdDescs, func() {
		keyDeriveCmd.Short = i18n.T("key_derive.short")
		keyDeriveCmd.Long = i18n.T("key_derive.long")
	})

	// Command-specific validation rules, registered so the declarative Field
	// rules can reference them (see validateFields in standard.go).
	param.RegisterRule("key_derive_input", func(args []string, flagName string, _ param.FieldValues) func(string) error {
		return func(v string) error { return validation.ValidateKeyDeriveInput(v) }
	})
	param.RegisterRule("key_derive_password", func(args []string, flagName string, _ param.FieldValues) func(string) error {
		return func(v string) error { return validation.ValidateKeyDerivePassword(v) }
	})

	// Namespace the prompt/option i18n keys (key_derive.prompt.* /
	// key_derive.option.*) so they do not collide with the shared
	// "standard" namespace used by the placeholder standard command.
	for _, e := range kdParams.fieldEntries() {
		e.field.PromptKeyPrefix = "key_derive"
	}

	kdParams.Mode.Allowed = []string{"generate", "restore"}
	kdParams.Mode.Interactive = true
	kdParams.Mode.PromptType = param.PromptSelect
	kdParams.Mode.PromptDefault = "generate"

	kdParams.Input.Required = true
	kdParams.Input.Interactive = true
	kdParams.Input.RequiredNonInteractive = true
	kdParams.Input.PromptType = param.PromptMultiInput
	kdParams.Input.PromptHelp = true
	kdParams.Input.Rules = []param.Rule{{Name: "key_derive_input"}}

	kdParams.Password.Required = true
	kdParams.Password.Interactive = true
	kdParams.Password.RequiredNonInteractive = true
	kdParams.Password.PromptType = param.PromptPassword
	kdParams.Password.Rules = []param.Rule{{Name: "key_derive_password"}}

	// hint/strength/output are only meaningful for generate; config only for
	// restore. Their visibility follows the resolved mode.
	kdParams.Hint.Interactive = true
	kdParams.Hint.PromptType = param.PromptInput
	kdParams.Hint.PromptHelp = true
	kdParams.Hint.Visible = func(v param.FieldValues) bool { return v["mode"] == "generate" }

	kdParams.Strength.Allowed = []string{"basic", "medium", "advanced"}
	kdParams.Strength.Interactive = true
	kdParams.Strength.PromptType = param.PromptSelect
	kdParams.Strength.PromptDefault = "medium"
	kdParams.Strength.Visible = func(v param.FieldValues) bool { return v["mode"] == "generate" }

	kdParams.Config.Required = true
	kdParams.Config.Interactive = true
	kdParams.Config.RequiredNonInteractive = true
	kdParams.Config.PromptType = param.PromptInput
	kdParams.Config.PromptHelp = true
	kdParams.Config.Visible = func(v param.FieldValues) bool { return v["mode"] == "restore" }

	kdParams.Output.Interactive = true
	kdParams.Output.PromptType = param.PromptInput
	kdParams.Output.PromptDefault = "recovery-config.txt"
	kdParams.Output.Visible = func(v param.FieldValues) bool { return v["mode"] == "generate" }

	// salt is a pure flag (reproducible runs), never prompted.

	// Non-interactive defaults mirror the interactive prompt defaults for
	// mode and strength. output is deliberately NOT defaulted in batch mode:
	// like the old implementation, a non-interactive generate prints the
	// recovery config to stdout unless --output is given, while the
	// interactive prompt offers "recovery-config.txt" via PromptDefault.
	// restore never defaults strength/output here so the recovery config
	// can supply them (see runKeyDeriveRestore).
	kdParams.afterStandardize = func(p *keyDeriveParams) error {
		if !param.IsStdinTerminal() {
			p.Mode.ApplyPromptDefaultNonInteractive()
			if p.Mode.Value == "generate" {
				p.Strength.ApplyPromptDefaultNonInteractive()
			}
		}
		return nil
	}

	keyDeriveCmd.Flags().StringVar(&kdParams.Mode.Value, "mode", "", i18n.T("key_derive.flag.mode"))
	keyDeriveCmd.Flags().StringVarP(&kdParams.Input.Value, "input", "i", "", i18n.T("key_derive.flag.input"))
	keyDeriveCmd.Flags().StringVarP(&kdParams.Password.Value, "password", "p", "", i18n.T("key_derive.flag.password"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Hint.Value, "hint", "", i18n.T("key_derive.flag.hint"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Strength.Value, "strength", "", i18n.T("key_derive.flag.strength"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Config.Value, "config", "", i18n.T("key_derive.flag.config"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Output.Value, "output", "", i18n.T("key_derive.flag.output"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Salt.Value, "salt", "", i18n.T("key_derive.flag.salt"))
	rootCmd.AddCommand(keyDeriveCmd)
}

// runKeyDeriveGenerate derives a fresh key set with a new random salt (or the
// one provided via --salt, for reproducible runs) and emits the keys + a
// recovery config (to stdout and/or --output).
func runKeyDeriveGenerate(p *keyDeriveParams, input, password, hint string, strength kdf.Strength) error {
	salt := p.Salt.Value
	if salt == "" {
		salt = kdf.GenerateSalt(64)
	}
	return deriveAndEmit(p, input, password, salt, hint, strength, nil)
}

// runKeyDeriveRestore re-derives the key set using the salt from an existing
// recovery config and verifies the result against the stored UUIDs.
func runKeyDeriveRestore(p *keyDeriveParams, input, password, hint string, strength kdf.Strength) error {
	cfg, err := loadRecoveryConfig(p.Config.Value)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_read_failed"), err)
	}
	if cfg.Salt == "" {
		return fmt.Errorf("%s", i18n.T("key_derive.error.config_missing_salt"))
	}
	// Use the strength from the config if the user did not override it
	// (restore never applies a non-interactive default to strength).
	if p.Strength.Value == "" && cfg.Strength != "" {
		strength = kdf.Strength(cfg.Strength)
	}
	if p.Hint.Value == "" && cfg.Hint != "" {
		hint = cfg.Hint
	}
	return deriveAndEmit(p, input, password, cfg.Salt, hint, strength, cfg)
}

// deriveAndEmit runs DeriveKeySet and prints/writes the results. In restore
// mode (stored != nil) it also checks ValidateKeyRecovery against stored UUIDs.
func deriveAndEmit(p *keyDeriveParams, input, password, salt, hint string, strength kdf.Strength, stored *recoveryConfig) error {
	result := kdf.DeriveKeySet(input, password, salt, strength)
	if !result.Success {
		return fmt.Errorf("%s: %s", i18n.T("key_derive.error.derive_failed"), result.Error)
	}

	// Restore verification runs BEFORE any output: a failed restore must not
	// leak the re-derived keys/details to stdout and must not write the config
	// file. Only a successful restore (or generate) prints details.
	if stored != nil && len(stored.UUIDs) > 0 {
		restoreOK := false
		for _, k := range result.Keys {
			if kdf.ValidateKeyRecovery(k, stored.UUIDs) {
				restoreOK = true
				break
			}
		}
		if !restoreOK {
			// The message is printed to stderr by Execute(); we must NOT also
			// fmt.Println it (that would duplicate the message on stdout).
			// SilenceUsage on the command keeps cobra from dumping the help
			// text after a verification failure (it's not an argument error).
			return fmt.Errorf("%s", i18n.T("key_derive.output.restore_failed"))
		}
	}

	cfgLabel := strengthConfigLabel(result.Strength)
	fmt.Println(i18n.TWithData("key_derive.output.algorithm", map[string]interface{}{
		"Strength": cfgLabel,
	}))
	fmt.Println(i18n.TWithData("key_derive.output.uuid", map[string]interface{}{
		"UUID": result.UUID,
	}))
	for i, k := range result.Keys {
		fmt.Println(i18n.TWithData("key_derive.output.key", map[string]interface{}{
			"Name": fmt.Sprintf("S%d", i+1),
			"Key":  k,
		}))
	}
	fmt.Println(i18n.TWithData("key_derive.output.processing_time", map[string]interface{}{
		"Ms": result.ProcessingTime,
	}))

	// Build the recovery config to print/save. In restore mode we preserve the
	// originally stored uuids/hint_ids so the saved file stays self-consistent.
	rc := buildRecoveryConfig(result, hint)
	if stored != nil {
		if len(stored.UUIDs) > 0 {
			rc.UUIDs = stored.UUIDs
		}
		if len(stored.HintIDs) > 0 {
			rc.HintIDs = stored.HintIDs
		}
	}
	configText := formatFrontendRecoveryConfig(rc, result.Keys)

	if p.Output.Value != "" {
		if err := os.WriteFile(p.Output.Value, []byte(configText), 0o600); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("key_derive.error.write_output_failed"), err)
		}
		fmt.Println(i18n.TWithData("key_derive.output.config_written", map[string]interface{}{
			"Path": p.Output.Value,
		}))
	} else {
		fmt.Println(i18n.T("key_derive.output.config_label"))
		fmt.Println(configText)
	}

	if stored != nil {
		fmt.Println(i18n.T("key_derive.output.restore_success"))
	}
	return nil
}

// cleanKeyDeriveText delegates to validation.CleanText.
func cleanKeyDeriveText(s string) string {
	return validation.CleanText(s)
}

// firstNChars returns the first n runes of s (rune-safe, not byte-safe).
func firstNChars(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// strengthConfigLabel returns a human-readable label for a strength tier.
func strengthConfigLabel(s kdf.Strength) string {
	switch s {
	case kdf.StrengthBasic:
		return i18n.T("key_derive.output.strength_label_basic")
	case kdf.StrengthAdvanced:
		return i18n.T("key_derive.output.strength_label_advanced")
	default:
		return i18n.T("key_derive.output.strength_label_medium")
	}
}
