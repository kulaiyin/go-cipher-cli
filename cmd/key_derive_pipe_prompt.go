package cmd

// Interactive (TTY) branch of key-derive-pipe. When stdin is a terminal the
// command collects mode/input/password/hint/strength/config/output via
// interactive prompts instead of a piped JSON object. Unlike key-derive's
// declarative param.Field lifecycle, the pipe layer owns a hand-rolled prompt
// flow so the password and the derived password material stay as wipeable
// []byte end to end.

import (
	"fmt"
	"os"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/password"
	"go-cipher-cli/internal/util"
	"go-cipher-cli/internal/validation"
)

// keyDerivePipeInteractiveState is the collected TTY input. Password is
// wipeable []byte; the remaining fields are public metadata (input/hint/salt
// are probe text and salts, config/output are paths).
type keyDerivePipeInteractiveState struct {
	Mode     string
	Input    string
	Salt     string
	Hint     string
	Strength kdf.Strength
	Output   string
	Config   string
	HintIDs  []string
	UUIDs    []string
	Password []byte
}

// runKeyDerivePipeInteractive is the TTY entry: it collects all inputs (the
// password as wipeable bytes), derives with DeriveKeySetBytes, and emits the
// recovery config (generate) or verifies the fingerprints (restore). The
// password is wiped on return.
func runKeyDerivePipeInteractive() error {
	state, err := collectKeyDerivePipeInteractive()
	if err != nil {
		return err
	}
	defer util.WipeBytes(state.Password)
	state.Input = cleanKeyDeriveText(state.Input)
	if err := validation.ValidateKeyDeriveInput(state.Input); err != nil {
		return err
	}
	if state.Hint == "" {
		state.Hint = firstNChars(state.Input, 10)
	}
	if state.Mode == "restore" {
		return runKeyDerivePipeInteractiveRestore(state)
	}
	return runKeyDerivePipeInteractiveGenerate(state)
}

// collectKeyDerivePipeInteractive runs the interactive prompts in the exact
// order of key-derive's flow. generate: mode -> input -> hint -> (QnA |
// password) -> strength -> output. restore: mode -> config -> input ->
// (re-answered QnA | password). Prompts, help text, option labels, and
// defaults reuse key-derive's i18n keys so the two commands look identical.
func collectKeyDerivePipeInteractive() (*keyDerivePipeInteractiveState, error) {
	state := &keyDerivePipeInteractiveState{Strength: kdf.StrengthMedium}

	mode, err := pipeSelectLabeled(
		i18n.T("key_derive.prompt.mode"),
		[]labelValue{
			{i18n.T("key_derive.option.mode.generate"), "generate"},
			{i18n.T("key_derive.option.mode.restore"), "restore"},
		},
		i18n.T("key_derive.option.mode.generate"), "",
	)
	if err != nil {
		return nil, err
	}
	state.Mode = mode

	if mode == "generate" {
		return collectKeyDerivePipeGenerate(state)
	}
	return collectKeyDerivePipeRestore(state)
}

// collectKeyDerivePipeGenerate prompts generate-mode fields in key-derive's
// order: input (multi-line + help) -> hint (empty default) -> salt + password
// (QnA or hidden prompt) -> strength -> output (volatile mntemp default).
func collectKeyDerivePipeGenerate(state *keyDerivePipeInteractiveState) (*keyDerivePipeInteractiveState, error) {
	input, err := param.MultiInput(i18n.T("key_derive.prompt.input"), i18n.T("key_derive.prompt.input_help"))
	if err != nil {
		return nil, err
	}
	state.Input = input

	hint, err := param.Input(i18n.T("key_derive.prompt.hint"), "", i18n.T("key_derive.prompt.hint_help"))
	if err != nil {
		return nil, err
	}
	state.Hint = hint

	state.Salt = kdf.GenerateSalt(64)
	pw, ids, err := collectPipePasswordQnA(state.Salt)
	if err != nil {
		return nil, err
	}
	state.Password = pw
	state.HintIDs = ids

	strength, err := pipeSelectLabeled(
		i18n.T("key_derive.prompt.strength"),
		[]labelValue{
			{i18n.T("key_derive.option.strength.basic"), "basic"},
			{i18n.T("key_derive.option.strength.medium"), "medium"},
			{i18n.T("key_derive.option.strength.advanced"), "advanced"},
		},
		i18n.T("key_derive.option.strength.medium"), "",
	)
	if err != nil {
		return nil, err
	}
	state.Strength = kdf.Strength(strength)

	def := mntempSaveDefault("key-derive", "recovery-config.txt")
	if err := inputOutputPath(i18n.T("key_derive.prompt.output"), def, &state.Output); err != nil {
		return nil, err
	}

	if err := validatePasswordBytes(state.Password); err != nil {
		return nil, err
	}
	return state, nil
}

// collectKeyDerivePipeRestore prompts restore-mode fields in key-derive's
// order: config (help) -> input (multi-line + help) -> password (re-answered
// QnA when the config stored question IDs, otherwise a hidden prompt).
func collectKeyDerivePipeRestore(state *keyDerivePipeInteractiveState) (*keyDerivePipeInteractiveState, error) {
	cfgPath, err := param.Input(i18n.T("key_derive.prompt.config"), "", i18n.T("key_derive.prompt.config_help"))
	if err != nil {
		return nil, err
	}
	state.Config = cfgPath

	cfg, err := loadRecoveryConfig(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_read_failed"), err)
	}
	if cfg.Salt == "" {
		return nil, fmt.Errorf("%s", i18n.T("key_derive.error.config_missing_salt"))
	}
	state.Salt = cfg.Salt
	state.UUIDs = cfg.UUIDs
	if cfg.Strength != "" {
		state.Strength = kdf.Strength(cfg.Strength)
	}
	if cfg.Hint != "" {
		state.Hint = cfg.Hint
		fmt.Fprintln(os.Stderr, i18n.TWithData("key_derive.output.restore_hint", map[string]interface{}{
			"Hint": cfg.Hint,
		}))
	}

	input, err := param.MultiInput(i18n.T("key_derive.prompt.input"), i18n.T("key_derive.prompt.input_help"))
	if err != nil {
		return nil, err
	}
	state.Input = input

	if len(cfg.HintIDs) > 0 {
		steps, err := buildRestoreSteps(cfg.HintIDs)
		if err != nil {
			return nil, err
		}
		pw, err := runReanswerFlowBytes(steps, cfg.Salt)
		if err != nil {
			return nil, err
		}
		state.Password = pw
		state.HintIDs = cfg.HintIDs
	} else {
		pw, err := param.Password(i18n.T("key_derive.prompt.password"), "")
		if err != nil {
			return nil, err
		}
		state.Password = pw
	}

	if err := validatePasswordBytes(state.Password); err != nil {
		return nil, err
	}
	return state, nil
}

// labelValue pairs a Select display label with its canonical value.
type labelValue struct {
	label string
	value string
}

// pipeSelectLabeled runs param.Select with localized option labels and maps the
// chosen label back to its canonical value, matching key-derive's option
// handling.
func pipeSelectLabeled(message string, opts []labelValue, defaultLabel string, help string) (string, error) {
	labels := make([]string, len(opts))
	labelToValue := make(map[string]string, len(opts))
	for i, o := range opts {
		labels[i] = o.label
		labelToValue[o.label] = o.value
	}
	chosen, err := param.Select(message, labels, defaultLabel, help)
	if err != nil {
		return "", err
	}
	return labelToValue[chosen], nil
}

// collectPipePasswordQnA collects the generate password: the question-answer
// high-strength flow by default (password returned as wipeable bytes), or a
// plain hidden password prompt when declined.
func collectPipePasswordQnA(salt string) ([]byte, []string, error) {
	useQnA, err := param.Confirm(i18n.T("key_derive.prompt.use_question_answer"), true)
	if err != nil {
		return nil, nil, err
	}
	if !useQnA {
		pw, err := param.Password(i18n.T("key_derive.prompt.password"), "")
		if err != nil {
			return nil, nil, err
		}
		return pw, nil, nil
	}
	return runQuestionAnswerFlowBytes(salt)
}

// runQuestionAnswerFlowBytes runs the web-style 3-step question-answer form
// and derives the high-strength password as wipeable bytes (via
// password.ComputeFinalPasswordBytes), returning it with the chosen question
// IDs. Answers are wiped after the derivation.
func runQuestionAnswerFlowBytes(salt string) ([]byte, []string, error) {
	steps, err := loadFormSteps(localizedConfigPath())
	if err != nil {
		return nil, nil, err
	}
	results, err := form.Run(steps, form.WithFinalPassword(finalPasswordBytes(salt)))
	if err != nil {
		return nil, nil, err
	}
	pw, err := password.ComputeFinalPasswordBytes(salt, finalAnswers(results))
	ids := resultIDs(results)
	wipeAnswers(results)
	if err != nil {
		return nil, nil, err
	}
	return pw, ids, nil
}

// runReanswerFlowBytes re-answers the reconstructed restore questions without
// the summary confirmation and computes the high-strength password as wipeable
// bytes. Answers are wiped after the derivation.
func runReanswerFlowBytes(steps [][]form.Step, salt string) ([]byte, error) {
	results, err := form.Run(steps, form.WithSkipConfirm(), form.WithFinalPassword(finalPasswordBytes(salt)))
	if err != nil {
		return nil, err
	}
	pw, err := password.ComputeFinalPasswordBytes(salt, finalAnswers(results))
	wipeAnswers(results)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// finalPasswordBytes returns the form's final-password generator that derives
// the wipeable high-strength password from the collected answers.
func finalPasswordBytes(salt string) func([]form.Result) []byte {
	return func(results []form.Result) []byte {
		pw, err := password.ComputeFinalPasswordBytes(salt, finalAnswers(results))
		if err != nil {
			return nil
		}
		return pw
	}
}

// writeKeySetBytesFile writes the derived keys to path with 0600 permissions,
// building the content byte-by-byte so no full-key string copy is kept after
// the write.
func writeKeySetBytesFile(path string, r kdf.KeySetBytesResult) error {
	buf := make([]byte, 0, 4*4+3*64+16)
	buf = append(buf, "S1: "...)
	buf = appendKeyHexBytes(buf, r.RawKeys[0])
	buf = append(buf, "\nS2: "...)
	buf = appendKeyHexBytes(buf, r.RawKeys[1])
	buf = append(buf, "\nS3: "...)
	buf = appendKeyHexBytes(buf, r.RawKeys[2])
	buf = append(buf, "\nUUID: "...)
	buf = appendKeyHexBytes(buf, r.RawUUID)
	buf = append(buf, '\n')
	defer clear(buf)
	return os.WriteFile(path, buf, 0o600)
}

// emitKeySetBytesFile exports the complete derived keys to a 0600 file in the
// volatile memory-backed mntemp directory, so an interactive generate/restore
// can hand the user their keys without printing them to the terminal. The
// mntemp note warns the file vanishes on shutdown.
func emitKeySetBytesFile(r kdf.KeySetBytesResult) error {
	path := mntempSaveDefault("key-derive", "keys.txt")
	if err := writeKeySetBytesFile(path, r); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("key_derive.error.write_output_failed"), err)
	}
	fmt.Println(i18n.TWithData("key_derive.output.keys_written", map[string]interface{}{
		"Path": path,
	}))
	return nil
}

// runKeyDerivePipeInteractiveGenerate derives a fresh key set with a random
// salt and writes the recovery config to the chosen file (0600) or stdout, then
// exports the complete keys to the volatile memory-backed directory. The
// rendered config carries only masked fingerprints, so printing it to the
// terminal does not leak the keys.
func runKeyDerivePipeInteractiveGenerate(state *keyDerivePipeInteractiveState) error {
	result := kdf.DeriveKeySetBytes(state.Input, state.Password, state.Salt, state.Strength)
	if !result.Success {
		return fmt.Errorf("%s: %s", i18n.T("key_derive.error.derive_failed"), result.Error)
	}
	defer wipeKeySetBytesResult(result)

	rc := buildPipeRecoveryConfig(result, state.Hint, state.HintIDs)
	configText := formatFrontendRecoveryConfigBytes(rc, result.RawKeys, result.RawUUID)
	defer util.WipeBytes(configText)

	if state.Output != "" {
		if err := os.WriteFile(state.Output, configText, 0o600); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("key_derive.error.write_output_failed"), err)
		}
		fmt.Println(i18n.TWithData("key_derive.output.config_written", map[string]interface{}{
			"Path": state.Output,
		}))
	} else {
		os.Stdout.Write(configText)
	}
	if err := emitKeySetBytesFile(result); err != nil {
		return err
	}
	return nil
}

// runKeyDerivePipeInteractiveRestore re-derives with the salt from the config,
// verifies the masked fingerprints of the derived keys against the stored
// uuids, and — on success — emits the rebuilt recovery config (preserving the
// stored uuids/hint_ids) so the keys can be saved again. Nothing sensitive is
// printed except the masked config.
func runKeyDerivePipeInteractiveRestore(state *keyDerivePipeInteractiveState) error {
	result := kdf.DeriveKeySetBytes(state.Input, state.Password, state.Salt, state.Strength)
	if !result.Success {
		return fmt.Errorf("%s: %s", i18n.T("key_derive.error.derive_failed"), result.Error)
	}
	defer wipeKeySetBytesResult(result)

	matched := false
	for _, raw := range result.RawKeys {
		if kdf.ValidateKeyRecoveryBytes(raw, state.UUIDs) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("%s", i18n.T("key_derive.output.restore_failed"))
	}

	rc := buildPipeRecoveryConfig(result, state.Hint, state.HintIDs)
	if len(state.UUIDs) > 0 {
		rc.UUIDs = state.UUIDs
	}
	if len(state.HintIDs) > 0 {
		rc.HintIDs = state.HintIDs
	}
	configText := formatFrontendRecoveryConfigBytes(rc, result.RawKeys, result.RawUUID)
	defer util.WipeBytes(configText)

	fmt.Println(i18n.T("key_derive.output.config_label"))
	os.Stdout.Write(configText)
	fmt.Println()
	if err := emitKeySetBytesFile(result); err != nil {
		return err
	}
	fmt.Println(i18n.T("key_derive.output.restore_success"))
	return nil
}
