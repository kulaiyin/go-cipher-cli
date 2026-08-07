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
	if state.Mode == "restore" {
		return runKeyDerivePipeInteractiveRestore(state)
	}
	return runKeyDerivePipeInteractiveGenerate(state)
}

// collectKeyDerivePipeInteractive runs the interactive prompts in the same
// order as key-derive's flow: mode -> input -> (QnA | password) -> hint ->
// strength -> output (generate), or input -> config -> (re-answered QnA |
// password) (restore).
func collectKeyDerivePipeInteractive() (*keyDerivePipeInteractiveState, error) {
	state := &keyDerivePipeInteractiveState{Strength: kdf.StrengthMedium}

	mode, err := param.Select(i18n.T("key_derive_pipe.prompt.mode"), []string{"generate", "restore"}, "generate", "")
	if err != nil {
		return nil, err
	}
	state.Mode = mode

	if mode == "generate" {
		input, err := param.MultiInput(i18n.T("key_derive_pipe.prompt.input"), "")
		if err != nil {
			return nil, err
		}
		state.Input = input
		state.Salt = kdf.GenerateSalt(64)

		pw, ids, err := collectPipePasswordQnA(state.Salt)
		if err != nil {
			return nil, err
		}
		state.Password = pw
		state.HintIDs = ids

		hint, err := param.Input(i18n.T("key_derive_pipe.prompt.hint"), firstNChars(cleanKeyDeriveText(input), 10), "")
		if err != nil {
			return nil, err
		}
		state.Hint = hint

		strength, err := param.Select(i18n.T("key_derive_pipe.prompt.strength"), []string{"basic", "medium", "advanced"}, "medium", "")
		if err != nil {
			return nil, err
		}
		state.Strength = kdf.Strength(strength)

		output, err := param.Input(i18n.T("key_derive_pipe.prompt.output"), "recovery-config.txt", "")
		if err != nil {
			return nil, err
		}
		state.Output = output
		return state, nil
	}

	// restore
	input, err := param.MultiInput(i18n.T("key_derive_pipe.prompt.input"), "")
	if err != nil {
		return nil, err
	}
	state.Input = input

	cfgPath, err := param.Input(i18n.T("key_derive_pipe.prompt.config"), "", "")
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
		fmt.Fprintln(os.Stderr, i18n.TWithData("key_derive.output.restore_hint", map[string]interface{}{
			"Hint": cfg.Hint,
		}))
	}

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
		pw, err := param.Password(i18n.T("key_derive_pipe.prompt.password"), "")
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

// collectPipePasswordQnA collects the generate password: the question-answer
// high-strength flow by default (password returned as wipeable bytes), or a
// plain hidden password prompt when declined.
func collectPipePasswordQnA(salt string) ([]byte, []string, error) {
	useQnA, err := param.Confirm(i18n.T("key_derive.prompt.use_question_answer"), true)
	if err != nil {
		return nil, nil, err
	}
	if !useQnA {
		pw, err := param.Password(i18n.T("key_derive_pipe.prompt.password"), "")
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

// runKeyDerivePipeInteractiveGenerate derives a fresh key set with a random
// salt and writes the recovery config to the chosen file (0600) or stdout. The
// rendered config carries only masked key fingerprints, so printing it to the
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
		return nil
	}
	os.Stdout.Write(configText)
	return nil
}

// runKeyDerivePipeInteractiveRestore re-derives with the salt from the config
// and verifies the masked fingerprints of the derived keys against the stored
// uuids. Nothing sensitive is printed.
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
	fmt.Println(i18n.T("key_derive.output.restore_success"))
	return nil
}
