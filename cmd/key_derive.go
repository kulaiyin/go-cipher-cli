package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/password"
	"go-cipher-cli/internal/tmpmount"
	"go-cipher-cli/internal/validation"
)

// keyDeriveKeyDriveVersion mirrors the frontend KEY_DRIVE_VERSION
// (packages/web/src/constant/const.ts). Stored in recovery configs so a future
// incompatible derivation change can be detected.
const keyDeriveKeyDriveVersion = "1.0.0"

// keyDeriveParams declares the parameters of the key-derive command using the
// declarative standard mode: type metadata, requiredness, validation rules,
// and interactive prompting are expressed as param.Field declarations instead
// of hand-written prompt code (see mntemp.go for the reference pattern).
type keyDeriveParams struct {
	Mode     param.Field
	Input    param.Field
	Password param.Field
	Hint     param.Field
	Strength param.Field
	Config   param.Field
	Output   param.Field
	Salt     param.Field

	// UseConfigFile / ConfigFile are pure flags (never prompted, not part of
	// the declarative field lifecycle): they switch key-derive into the
	// edit-a-YAML-config input flow. ConfigFile optionally pins the config
	// path; empty means auto-generate under mntemp.
	UseConfigFile bool
	ConfigFile    string

	// loadedCfg caches the recovery config loaded during the restore prompt
	// pass so execute does not read the file twice.
	loadedCfg *recoveryConfig

	// answerIDs records the question IDs chosen during a question-answer
	// password generation so they can be written into the recovery config.
	answerIDs []string
	// restoreSteps caches the questions reconstructed from the config's hint
	// IDs so restore can re-answer them to regenerate the password.
	restoreSteps [][]form.Step
}

var kdParams keyDeriveParams

var keyDeriveCmd = &cobra.Command{
	Use:          "key-derive --mode <generate|restore> -i <input> -p <password> [flags]",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// --use-config-file takes a fully custom flow (editor-driven input
		// collection); otherwise drive the shared declarative lifecycle and
		// runKeyDerive executes the body.
		if kdParams.UseConfigFile {
			return runKeyDeriveWithConfigFile(&kdParams)
		}
		// Standardize first, then a key-derive-specific prompt pass that loads
		// the recovery config up front in restore mode, then the shared prompt
		// loop for the remaining fields.
		if err := kdSet.standardize(&kdParams); err != nil {
			return err
		}
		if err := promptKeyDerive(&kdParams); err != nil {
			return err
		}
		return runKeyDerive(&kdParams)
	},
}

func (p *keyDeriveParams) fieldEntries() []fieldEntry {
	return []fieldEntry{
		{&p.Mode, &p.Mode.Value, "mode"},
		{&p.Input, &p.Input.Value, "input"},
		{&p.Hint, &p.Hint.Value, "hint"},
		{&p.Password, &p.Password.Value, "password"},
		{&p.Strength, &p.Strength.Value, "strength"},
		{&p.Config, &p.Config.Value, "config"},
		{&p.Output, &p.Output.Value, "output"},
		{&p.Salt, &p.Salt.Value, "salt"},
	}
}

// kdSet drives the shared declarative lifecycle for the key-derive command:
// normalize + validate, non-interactive defaults, and the derive/verify body.
var kdSet = paramSet[keyDeriveParams]{
	fields: func(p *keyDeriveParams) []fieldEntry { return p.fieldEntries() },
	normalize: func(p *keyDeriveParams) {
		p.Mode.Value = strings.ToLower(strings.TrimSpace(p.Mode.Value))
	},
	afterStandardize: func(p *keyDeriveParams) error {
		// Non-interactive defaults mirror the interactive prompt defaults for
		// mode and strength. output is deliberately NOT defaulted in batch
		// mode: a non-interactive generate prints the recovery config to
		// stdout unless --output is given, while the interactive prompt offers
		// "recovery-config.txt" via PromptDefault. restore never defaults
		// strength/output here so the recovery config can supply them.
		if !param.IsStdinTerminal() {
			p.Mode.ApplyPromptDefaultNonInteractive()
			if p.Mode.Value == "generate" {
				p.Strength.ApplyPromptDefaultNonInteractive()
			}
		}
		// Pre-generate the salt seed for generate mode so the question-answer
		// password flow (prompted later) shares the same salt used for key
		// derivation, mirroring the web tool where salt_seed is created up
		// front and reused by both the password modal and deriveKey.
		preGenerateSaltSeed(p)
		return nil
	},
	execute: runKeyDerive,
}

// runKeyDerive executes the command after all params are resolved (flags +
// interactive): it cleans input/password like the frontend, applies the hint
// default, and dispatches to generate or restore.
func runKeyDerive(p *keyDeriveParams) error {
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
	kdParams.Password.PromptFn = promptPasswordWithQuestionAnswer

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

	keyDeriveCmd.Flags().StringVar(&kdParams.Mode.Value, "mode", "", i18n.T("key_derive.flag.mode"))
	keyDeriveCmd.Flags().StringVarP(&kdParams.Input.Value, "input", "i", "", i18n.T("key_derive.flag.input"))
	keyDeriveCmd.Flags().StringVarP(&kdParams.Password.Value, "password", "p", "", i18n.T("key_derive.flag.password"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Hint.Value, "hint", "", i18n.T("key_derive.flag.hint"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Strength.Value, "strength", "", i18n.T("key_derive.flag.strength"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Config.Value, "config", "", i18n.T("key_derive.flag.config"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Output.Value, "output", "", i18n.T("key_derive.flag.output"))
	keyDeriveCmd.Flags().StringVar(&kdParams.Salt.Value, "salt", "", i18n.T("key_derive.flag.salt"))
	keyDeriveCmd.Flags().BoolVar(&kdParams.UseConfigFile, "use-config-file", false, i18n.T("key_derive.flag.use_config_file"))
	keyDeriveCmd.Flags().StringVar(&kdParams.ConfigFile, "config-file", "", i18n.T("key_derive.flag.config_file"))
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
	cfg := p.loadedCfg
	if cfg == nil {
		var err error
		cfg, err = loadAndApplyRecoveryConfig(p)
		if err != nil {
			return err
		}
	}
	// loadAndApplyRecoveryConfig backfilled strength/hint from the config when
	// the user did not override them, so recompute strength from the resolved
	// value (restore never applies a non-interactive default to strength).
	strength = kdf.Strength(p.Strength.Value)
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
	rc := buildRecoveryConfig(result, hint, p.answerIDs)
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

// preGenerateSaltSeed sets a fresh 64-byte salt seed for generate mode unless
// one was already provided via --salt, so the question-answer password flow
// and the key derivation share the same salt.
func preGenerateSaltSeed(p *keyDeriveParams) {
	if p.Mode.Value == "generate" && p.Salt.Value == "" {
		p.Salt.Value = kdf.GenerateSalt(64)
	}
}

// promptKeyDerive drives the interactive prompt pass. Restore mode loads the
// recovery config before any input is collected so failures surface early and
// strength/hint are backfilled from the config.
func promptKeyDerive(p *keyDeriveParams) error {
	if !param.IsStdinTerminal() {
		return nil
	}
	if p.Mode.Value == "" {
		if err := p.Mode.Prompt(&p.Mode.Value, "mode"); err != nil {
			return err
		}
	}
	// The mode is only known after the interactive prompt, so (re)generate the
	// salt for generate mode now: the QnA password and the derivation must
	// share the same salt, otherwise restore cannot reproduce the password.
	preGenerateSaltSeed(p)
	if p.Mode.Value == "restore" {
		if err := promptKeyDeriveRestoreConfig(p); err != nil {
			return err
		}
	} else if p.Output.Value == "" {
		p.Output.PromptFn = mntempOutputPrompt()
	}
	return promptInteractive(p.fieldEntries())
}

// mntempOutputPrompt returns the output field's custom prompt. It runs at save
// time (the output prompt, after all other inputs): when the volatile mntemp
// filesystem is mounted the default save location points into it; otherwise the
// user is asked whether to mount it (default yes). Declining or a failed mount
// falls back to the usual cwd default without extra output.
func mntempOutputPrompt() func(promptMsg string, target *string, flagName string) error {
	return func(promptMsg string, target *string, flagName string) error {
		defaultPath := "recovery-config.txt"
		root := tmpmount.DefaultMountPath(mntempDefaultName)
		if !tmpmount.IsMounted(root) {
			confirmed, err := param.Confirm(i18n.T("key_derive.prompt.mount_confirm"), true)
			if err != nil {
				return err
			}
			if !confirmed {
				return inputOutputPath(promptMsg, defaultPath, target)
			}
			if err := mountVolatile(root, mntempDefaultSizeMB, mntempDefaultName); err != nil {
				fmt.Fprintln(os.Stderr, i18n.TWithData("key_derive.error.mount_failed", map[string]interface{}{
					"Err": err,
				}))
				return inputOutputPath(promptMsg, defaultPath, target)
			}
		}
		dir, err := tmpmount.CommandDir(mntempDefaultName, "key-derive")
		if err == nil {
			defaultPath = filepath.Join(dir, "recovery-config.txt")
		}
		fmt.Println(i18n.TWithData("key_derive.output.mntemp_note", map[string]interface{}{
			"Path": defaultPath,
		}))
		return inputOutputPath(promptMsg, defaultPath, target)
	}
}

// inputOutputPath runs the plain output-path input prompt with the given default.
func inputOutputPath(promptMsg, defaultPath string, target *string) error {
	v, err := param.Input(promptMsg, defaultPath, "")
	if err != nil {
		return err
	}
	*target = v
	return nil
}

// promptKeyDeriveRestoreConfig collects the config path and loads it, caching
// the parsed config and backfilling strength/hint for the rest of the flow.
// When the config stores question IDs, the questions are reconstructed so the
// password can be regenerated from answers instead of typed directly.
func promptKeyDeriveRestoreConfig(p *keyDeriveParams) error {
	if p.Config.Value == "" {
		if err := p.Config.Prompt(&p.Config.Value, "config"); err != nil {
			return err
		}
	}
	cfg, err := loadAndApplyRecoveryConfig(p)
	if err != nil {
		return err
	}
	p.loadedCfg = cfg
	if cfg.Hint != "" {
		fmt.Println(i18n.TWithData("key_derive.output.restore_hint", map[string]interface{}{
			"Hint": cfg.Hint,
		}))
	}
	if len(cfg.HintIDs) > 0 {
		steps, err := buildRestoreSteps(cfg.HintIDs)
		if err != nil {
			return err
		}
		p.restoreSteps = steps
	}
	return nil
}

// loadAndApplyRecoveryConfig parses the config file, requires a salt, and
// backfills strength/hint into the params when not already set.
func loadAndApplyRecoveryConfig(p *keyDeriveParams) (*recoveryConfig, error) {
	cfg, err := loadRecoveryConfig(p.Config.Value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_read_failed"), err)
	}
	if cfg.Salt == "" {
		return nil, fmt.Errorf("%s", i18n.T("key_derive.error.config_missing_salt"))
	}
	if p.Strength.Value == "" && cfg.Strength != "" {
		p.Strength.Value = cfg.Strength
	}
	if p.Hint.Value == "" && cfg.Hint != "" {
		p.Hint.Value = cfg.Hint
	}
	return cfg, nil
}

// promptPasswordWithQuestionAnswer is the password field's custom interactive
// prompt. In generate mode it offers the web-style "question-answer" flow to
// generate a high-strength password. Restore mode re-answers the questions
// reconstructed from the config when the password was generated that way, and
// falls back to the plain hidden password prompt otherwise.
func promptPasswordWithQuestionAnswer(promptMsg string, target *string, flagName string) error {
	if kdParams.Mode.Value == "restore" {
		if len(kdParams.restoreSteps) > 0 {
			return promptRestoreAnswers(kdParams.loadedCfg, target)
		}
		return promptDefaultPassword(promptMsg, target)
	}
	useQnA, err := param.Confirm(i18n.T("key_derive.prompt.use_question_answer"), true)
	if err != nil {
		return err
	}
	if !useQnA {
		return promptDefaultPassword(promptMsg, target)
	}

	steps, err := loadFormSteps(localizedConfigPath())
	if err != nil {
		return err
	}
	salt := kdParams.Salt.Value
	results, err := form.Run(steps, form.WithFinalPassword(func(results []form.Result) string {
		pw, err := password.ComputeFinalPassword(salt, finalAnswers(results))
		if err != nil {
			return ""
		}
		return pw
	}))
	if err != nil {
		return err
	}
	kdParams.answerIDs = resultIDs(results)
	pw, err := password.ComputeFinalPassword(salt, finalAnswers(results))
	if err != nil {
		return err
	}
	*target = pw
	return nil
}

// promptRestoreAnswers re-answers the questions restored from the config so the
// original high-strength password can be regenerated from the answers and salt.
func promptRestoreAnswers(cfg *recoveryConfig, target *string) error {
	results, err := form.Run(kdParams.restoreSteps, form.WithSkipConfirm(), form.WithFinalPassword(func(results []form.Result) string {
		pw, err := password.ComputeFinalPassword(cfg.Salt, finalAnswers(results))
		if err != nil {
			return ""
		}
		return pw
	}))
	if err != nil {
		return err
	}
	pw, err := password.ComputeFinalPassword(cfg.Salt, finalAnswers(results))
	if err != nil {
		return err
	}
	*target = pw
	return nil
}

// buildRestoreSteps reconstructs one fixed question per step from the stored
// hint IDs so restore re-answers the same questions that generated the password.
func buildRestoreSteps(hintIDs []string) ([][]form.Step, error) {
	steps, err := loadFormSteps(localizedConfigPath())
	if err != nil {
		return nil, err
	}
	restore := make([][]form.Step, 0, len(hintIDs))
	for i, id := range hintIDs {
		if i >= len(steps) {
			break
		}
		found := -1
		for j := range steps[i] {
			if steps[i][j].ID == id {
				found = j
				break
			}
		}
		if found < 0 {
			return nil, fmt.Errorf("%s", i18n.TWithData("key_derive.error.hint_missing", map[string]interface{}{"ID": id}))
		}
		restore = append(restore, []form.Step{steps[i][found]})
	}
	return restore, nil
}

// promptDefaultPassword runs the standard hidden password prompt.
func promptDefaultPassword(promptMsg string, target *string) error {
	input, err := param.Password(promptMsg, "")
	if err != nil {
		return err
	}
	*target = input
	return nil
}

// finalAnswers extracts the per-step answers from form results, in step order.
func finalAnswers(results []form.Result) []string {
	answers := make([]string, len(results))
	for i, r := range results {
		answers[i] = r.Answer
	}
	return answers
}

// resultIDs extracts the per-step question IDs from form results, in step order.
func resultIDs(results []form.Result) []string {
	ids := make([]string, len(results))
	for i, r := range results {
		ids[i] = r.ID
	}
	return ids
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
