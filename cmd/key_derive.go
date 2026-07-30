package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/validation"
)

// keyDeriveKeyDriveVersion mirrors the frontend KEY_DRIVE_VERSION
// (packages/web/src/constant/const.ts). Stored in recovery configs so a future
// incompatible derivation change can be detected.
const keyDeriveKeyDriveVersion = "1.0.0"

var (
	keyDeriveMode     string
	keyDeriveInput    string
	keyDerivePassword string
	keyDeriveHint     string
	keyDeriveStrength string
	keyDeriveConfig   string
	keyDeriveOutput   string
	keyDeriveSalt     string
)

var keyDeriveCmd = &cobra.Command{
	Use:   "key-derive --mode <generate|restore> -i <input> -p <password> [flags]",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyDerive(cmd)
	},
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

	keyDeriveCmd.Flags().StringVar(&keyDeriveMode, "mode", "", i18n.T("key_derive.flag.mode"))
	keyDeriveCmd.Flags().StringVarP(&keyDeriveInput, "input", "i", "", i18n.T("key_derive.flag.input"))
	keyDeriveCmd.Flags().StringVarP(&keyDerivePassword, "password", "p", "", i18n.T("key_derive.flag.password"))
	keyDeriveCmd.Flags().StringVar(&keyDeriveHint, "hint", "", i18n.T("key_derive.flag.hint"))
	keyDeriveCmd.Flags().StringVar(&keyDeriveStrength, "strength", "", i18n.T("key_derive.flag.strength"))
	keyDeriveCmd.Flags().StringVar(&keyDeriveConfig, "config", "", i18n.T("key_derive.flag.config"))
	keyDeriveCmd.Flags().StringVar(&keyDeriveOutput, "output", "", i18n.T("key_derive.flag.output"))
	keyDeriveCmd.Flags().StringVar(&keyDeriveSalt, "salt", "", i18n.T("key_derive.flag.salt"))
	rootCmd.AddCommand(keyDeriveCmd)
}

// runKeyDerive dispatches between generate and restore after resolving all
// parameters (flag takes priority; missing values fall back to interactive
// survey prompts). stdin/stdout are used directly so the function stays testable.
func runKeyDerive(cmd *cobra.Command) error {
	mode := keyDeriveMode
	if mode == "" {
		// Non-interactive default is generate; interactive prompt only when a TTY
		// is available (survey degrades otherwise).
		if isStdinTerminal() {
			modeOpts := []struct {
				value string
				label string
			}{
				{"generate", i18n.T("key_derive.option.generate")},
				{"restore", i18n.T("key_derive.option.restore")},
			}
			modeLabels := make([]string, len(modeOpts))
			modeLabelToValue := make(map[string]string, len(modeOpts))
			for i, o := range modeOpts {
				modeLabels[i] = o.label
				modeLabelToValue[o.label] = o.value
			}
			p := &survey.Select{
				Message: i18n.T("key_derive.prompt.mode"),
				Options: modeLabels,
				Default: i18n.T("key_derive.option.generate"),
			}
			if err := survey.AskOne(p, &mode, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
			mode = modeLabelToValue[mode]
		} else {
			mode = "generate"
		}
	}
	if mode != "generate" && mode != "restore" {
		return fmt.Errorf("%s", i18n.TWithData("key_derive.error.invalid_mode", map[string]interface{}{
			"Mode": mode,
		}))
	}

	// Resolve shared params (flag first, then interactive fallback).
	if err := resolveKeyDeriveParams(mode); err != nil {
		return err
	}
	// Validate resolved params — covers the flag-provided path which bypasses
	// interactive survey validators (mirrors data_cipher.go's validateKeys()).
	if err := validateKeyDeriveParams(); err != nil {
		return err
	}
	// All params resolved OK: from here on, failures are runtime/crypto errors
	// (e.g. restore UUID mismatch), not argument errors. Silence the usage dump
	// so a verification failure doesn't get followed by the full help text —
	// the error message to stderr is enough. Argument errors (returned above,
	// before this point) still print usage as usual.
	cmd.SilenceUsage = true

	// Clean input/password exactly like the frontend (strip whitespace + NFC).
	cleanedInput := cleanKeyDeriveText(keyDeriveInput)
	cleanedPassword := cleanKeyDeriveText(keyDerivePassword)

	// Hint defaults to the first 10 chars of the input (frontend behaviour).
	hint := keyDeriveHint
	if hint == "" {
		hint = firstNChars(cleanedInput, 10)
	}

	strength := kdf.Strength(keyDeriveStrength)

	if mode == "restore" {
		return runKeyDeriveRestore(cleanedInput, cleanedPassword, hint, strength)
	}
	return runKeyDeriveGenerate(cleanedInput, cleanedPassword, hint, strength)
}

// runKeyDeriveGenerate derives a fresh key set with a new random salt (or the
// one provided via --salt, for reproducible runs) and emits the keys + a
// recovery config (to stdout and/or --output).
func runKeyDeriveGenerate(input, password, hint string, strength kdf.Strength) error {
	salt := keyDeriveSalt
	if salt == "" {
		salt = kdf.GenerateSalt(64)
	}
	return deriveAndEmit(input, password, salt, hint, strength, nil)
}

// runKeyDeriveRestore re-derives the key set using the salt from an existing
// recovery config and verifies the result against the stored UUIDs.
func runKeyDeriveRestore(input, password, hint string, strength kdf.Strength) error {
	cfg, err := loadRecoveryConfig(keyDeriveConfig)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_read_failed"), err)
	}
	if cfg.Salt == "" {
		return fmt.Errorf("%s", i18n.T("key_derive.error.config_missing_salt"))
	}
	// Use the strength from the config if the user did not override it.
	if keyDeriveStrength == "" && cfg.Strength != "" {
		strength = kdf.Strength(cfg.Strength)
	}
	if keyDeriveHint == "" && cfg.Hint != "" {
		hint = cfg.Hint
	}
	return deriveAndEmit(input, password, cfg.Salt, hint, strength, cfg)
}

// deriveAndEmit runs DeriveKeySet and prints/writes the results. In restore
// mode (stored != nil) it also checks ValidateKeyRecovery against stored UUIDs.
func deriveAndEmit(input, password, salt, hint string, strength kdf.Strength, stored *recoveryConfig) error {
	result := kdf.DeriveKeySet(input, password, salt, strength)
	if !result.Success {
		return fmt.Errorf("%s: %s", i18n.T("key_derive.error.derive_failed"), result.Error)
	}

	// Restore verification: any derived key matching a stored UUID = success.
	restoreOK := true
	if stored != nil && len(stored.UUIDs) > 0 {
		restoreOK = false
		for _, k := range result.Keys {
			if kdf.ValidateKeyRecovery(k, stored.UUIDs) {
				restoreOK = true
				break
			}
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

	if keyDeriveOutput != "" {
		if err := os.WriteFile(keyDeriveOutput, []byte(configText), 0o600); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("key_derive.error.write_output_failed"), err)
		}
		fmt.Println(i18n.TWithData("key_derive.output.config_written", map[string]interface{}{
			"Path": keyDeriveOutput,
		}))
	} else {
		fmt.Println(i18n.T("key_derive.output.config_label"))
		fmt.Println(configText)
	}

	if stored != nil {
		if restoreOK {
			fmt.Println(i18n.T("key_derive.output.restore_success"))
		} else {
			// Restore verification failed: the re-derived keys do not match the
			// stored UUIDs. This is a real failure (wrong input/password/strength),
			// so return an error so cobra exits with a non-zero status — letting
			// scripts and CI reliably detect it. The message is printed to stderr
			// by Execute(); we must NOT also fmt.Println it (that would duplicate
			// the message on stdout). SilenceUsage on the command keeps cobra from
			// dumping the help text after a verification failure (it's not an
			// argument error).
			return fmt.Errorf("%s", i18n.T("key_derive.output.restore_failed"))
		}
	}
	return nil
}

// resolveKeyDeriveParams fills in missing params interactively. strength and hint
// are optional (they have internal defaults); input/password/config are prompted
// only when missing AND stdin is a TTY. In non-interactive runs, optional params
// fall back to their defaults and required params produce an error.
//
// In restore mode, strength is NOT prompted here: it is read from the recovery
// config later (unless the user explicitly passed --strength).
func resolveKeyDeriveParams(mode string) error {
	if keyDeriveStrength == "" && mode == "generate" && isStdinTerminal() {
		strengthOpts := []struct {
			value string
			label string
		}{
			{"basic", i18n.T("key_derive.option.strength_basic")},
			{"medium", i18n.T("key_derive.option.strength_medium")},
			{"advanced", i18n.T("key_derive.option.strength_advanced")},
		}
		strengthLabels := make([]string, len(strengthOpts))
		strengthLabelToValue := make(map[string]string, len(strengthOpts))
		for i, o := range strengthOpts {
			strengthLabels[i] = o.label
			strengthLabelToValue[o.label] = o.value
		}
		p := &survey.Select{
			Message: i18n.T("key_derive.prompt.strength"),
			Options: strengthLabels,
			Default: i18n.T("key_derive.option.strength_medium"),
		}
		if err := survey.AskOne(p, &keyDeriveStrength, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
		keyDeriveStrength = strengthLabelToValue[keyDeriveStrength]
	}
	// restore: leave strength empty so it is taken from the config (or defaults to medium).

	if keyDeriveInput == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("key_derive.error.input_required"))
		}
		p := &survey.Multiline{
			Message: i18n.T("key_derive.prompt.input"),
			Help:    i18n.T("key_derive.prompt.input_help"),
		}
		if err := survey.AskOne(p, &keyDeriveInput, survey.WithValidator(i18nRequired()), survey.WithValidator(keyDeriveInputValidator)); err != nil {
			return err
		}
	}

	if keyDeriveHint == "" && mode == "generate" && isStdinTerminal() {
		p := &survey.Input{
			Message: i18n.T("key_derive.prompt.hint"),
			Help:    i18n.T("key_derive.prompt.hint_help"),
		}
		// Optional field: no Required validator, empty value falls back to
		// first 10 chars of input (set later in runKeyDerive).
		if err := survey.AskOne(p, &keyDeriveHint); err != nil {
			return err
		}
	}

	if keyDerivePassword == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("key_derive.error.password_required"))
		}
		p := &survey.Password{
			Message: i18n.T("key_derive.prompt.password"),
		}
		if err := survey.AskOne(p, &keyDerivePassword, survey.WithValidator(i18nRequired()), survey.WithValidator(keyDerivePasswordValidator)); err != nil {
			return err
		}
	}

	if keyDeriveOutput == "" && mode == "generate" && isStdinTerminal() {
		p := &survey.Input{
			Message: i18n.T("key_derive.prompt.output"),
			Default: "recovery-config.txt",
		}
		// Press Enter to accept the default; the file is written after derivation.
		if err := survey.AskOne(p, &keyDeriveOutput); err != nil {
			return err
		}
	}

	if mode == "restore" && keyDeriveConfig == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("key_derive.error.config_required"))
		}
		p := &survey.Input{
			Message: i18n.T("key_derive.prompt.config"),
			Help:    i18n.T("key_derive.prompt.config_help"),
		}
		if err := survey.AskOne(p, &keyDeriveConfig, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
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

// i18nRequired is an i18n-aware replacement for survey.Required. Handles both
// plain strings (Input / Password) and survey.OptionAnswer (Select / MultiSelect).
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

// validateKeyDeriveParams validates the package-level keyDeriveInput and
// keyDerivePassword after resolveKeyDeriveParams, ensuring flag-provided
// values also pass validation (mirrors data_cipher.go's validateKeys()).
func validateKeyDeriveParams() error {
	if keyDeriveInput != "" {
		if err := validation.ValidateKeyDeriveInput(keyDeriveInput); err != nil {
			return err
		}
	}
	if keyDerivePassword != "" {
		if err := validation.ValidateKeyDerivePassword(keyDerivePassword); err != nil {
			return err
		}
	}
	return nil
}

// keyDerivePasswordValidator wraps validation.ValidateKeyDerivePassword as a
// survey.Validator.
func keyDerivePasswordValidator(ans interface{}) error {
	s, ok := ans.(string)
	if !ok {
		return fmt.Errorf("%s", i18n.T("key_derive.error.validator_type_assert"))
	}
	return validation.ValidateKeyDerivePassword(s)
}

// keyDeriveInputValidator wraps validation.ValidateKeyDeriveInput as a
// survey.Validator.
func keyDeriveInputValidator(ans interface{}) error {
	s, ok := ans.(string)
	if !ok {
		return fmt.Errorf("%s", i18n.T("key_derive.error.validator_type_assert"))
	}
	return validation.ValidateKeyDeriveInput(s)
}

// isStdinTerminal reports whether stdin is an interactive terminal. Uses
// golang.org/x/term (already an indirect dependency) so /dev/null and pipes are
// correctly distinguished from real TTYs. When stdin is not a TTY the command
// skips survey prompts and relies on flags (or defaults) instead.
func isStdinTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
