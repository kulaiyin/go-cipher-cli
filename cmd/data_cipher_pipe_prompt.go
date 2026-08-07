package cmd

// Interactive (TTY) branch of data-cipher-pipe plus the shared secret
// resolution/validation used by both the TTY and piped flows. When stdin is a
// terminal the command prompts for mode/input/keys/passwords interactively;
// when the piped JSON is missing a secret it falls back to the TTY flow and
// reuses the already-provided fields. All secrets are wipeable []byte.
//
// These are new functions layered on top of the existing data-cipher
// implementation (aesgcm/container primitives and the shared prompt helpers);
// the legacy data_cipher.go command is left untouched.

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/safety"
)

// runDataCipherPipeInteractive is the TTY entry: it collects all inputs (the
// secrets as wipeable bytes), then dispatches to encrypt/decrypt. Decrypt's
// secrets are collected after the zip is parsed (its salt and selectedHints
// come from the bundle).
func runDataCipherPipeInteractive() error {
	params, err := collectDataCipherPipeInteractive()
	if err != nil {
		return err
	}
	defer wipeDataCipherPipeSecrets(params)
	if params.Mode == "encrypt" {
		return runDataCipherPipeEncrypt(params)
	}
	return runDataCipherPipeDecrypt(params)
}

// collectDataCipherPipeInteractive prompts in data-cipher's order: mode ->
// input-type -> content -> hint -> salt -> secrets (encrypt), or mode -> file
// (decrypt; its secrets are collected after the zip parse).
func collectDataCipherPipeInteractive() (*dataCipherPipeParams, error) {
	p := &dataCipherPipeParams{}

	mode, err := selectDataCipherPipeMode()
	if err != nil {
		return nil, err
	}
	p.Mode = mode

	if mode == "encrypt" {
		it, err := selectDataCipherPipeInputType()
		if err != nil {
			return nil, err
		}
		p.InputType = it
		if it == "text" {
			text, err := param.MultiInput(i18n.T("data_cipher.prompt.text"), "")
			if err != nil {
				return nil, err
			}
			p.Text = text
		} else {
			path, err := param.Input(i18n.T("data_cipher.prompt.input"), "", "")
			if err != nil {
				return nil, err
			}
			p.File = path
		}
		hint, err := param.MultiInput(i18n.T("data_cipher.prompt.hint"), i18n.T("data_cipher.prompt.hint_help"), param.WithoutRequired())
		if err != nil {
			return nil, err
		}
		p.Hint = strings.TrimSpace(hint)
		p.Salt = safety.BytesToHex(safety.GenerateRandomBytes(64))
		if err := collectDataCipherPipeInteractiveSecrets(p); err != nil {
			return nil, err
		}
	} else {
		path, err := param.Input(i18n.T("data_cipher.prompt.input"), "", "")
		if err != nil {
			return nil, err
		}
		p.File = path
	}
	return p, nil
}

// selectDataCipherPipeMode prompts for encrypt/decrypt with localized labels.
func selectDataCipherPipeMode() (string, error) {
	return pipeSelectLabeled(i18n.T("data_cipher.prompt.mode"), []labelValue{
		{i18n.T("data_cipher.option.encrypt"), "encrypt"},
		{i18n.T("data_cipher.option.decrypt"), "decrypt"},
	}, "", "")
}

// selectDataCipherPipeInputType prompts for file/text with localized labels.
func selectDataCipherPipeInputType() (string, error) {
	return pipeSelectLabeled(i18n.T("data_cipher.prompt.input_type"), []labelValue{
		{i18n.T("data_cipher.option.file"), "file"},
		{i18n.T("data_cipher.option.text"), "text"},
	}, "", "")
}

// collectDataCipherPipeInteractiveSecrets collects the encrypt secrets: the 3
// strong keys, password1 (question-answer or hidden), and one optional extra.
func collectDataCipherPipeInteractiveSecrets(p *dataCipherPipeParams) error {
	for i := 0; i < 3; i++ {
		v, err := param.Password(i18n.TWithData("data_cipher.prompt.key_n", map[string]interface{}{
			"N": i + 1,
		}), i18n.T("data_cipher.prompt.key_help"))
		if err != nil {
			return err
		}
		p.Keys = append(p.Keys, v)
	}
	pw, ids, err := collectDataCipherPipePassword1(p.Salt, true, nil)
	if err != nil {
		return err
	}
	p.Password1 = pw
	p.HintIDs = ids
	return collectDataCipherPipeOptionalPasswords(p)
}

// resolveDataCipherPipePasswords makes sure the 3 strong keys and password1 are
// present. When the piped JSON carried any of them, they are reused; the
// missing ones are collected interactively (redirecting to /dev/tty when stdin
// is the consumed pipe).
func resolveDataCipherPipePasswords(p *dataCipherPipeParams, salt string, allowQnA bool, hintIDs []string) error {
	if len(p.Keys) >= 3 && len(p.Password1) > 0 {
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		restore, err := redirectStdinToTTY()
		if err != nil {
			return fmt.Errorf("%s", i18n.T("data_cipher.error.password_required"))
		}
		defer restore()
	}
	return collectDataCipherPipeMissingSecrets(p, salt, allowQnA, hintIDs)
}

// collectDataCipherPipeMissingSecrets fills only the missing secrets: any of
// the 3 strong keys not supplied, password1 when absent, and the optional extra
// password (collected on a TTY so decrypt matches whatever the encrypt run used;
// an empty answer means none).
func collectDataCipherPipeMissingSecrets(p *dataCipherPipeParams, salt string, allowQnA bool, hintIDs []string) error {
	for i := len(p.Keys); i < 3; i++ {
		v, err := param.Password(i18n.TWithData("data_cipher.prompt.key_n", map[string]interface{}{
			"N": i + 1,
		}), i18n.T("data_cipher.prompt.key_help"))
		if err != nil {
			return err
		}
		p.Keys = append(p.Keys, v)
	}
	if len(p.Password1) == 0 {
		pw, ids, err := collectDataCipherPipePassword1(salt, allowQnA, hintIDs)
		if err != nil {
			return err
		}
		p.Password1 = pw
		p.HintIDs = ids
	}
	if len(p.Extras) == 0 && term.IsTerminal(int(os.Stdin.Fd())) {
		return collectDataCipherPipeOptionalPasswords(p)
	}
	return nil
}

// collectDataCipherPipeOptionalPasswords collects the optional additional
// passwords (web keys[4..]), mirroring data-cipher's interactive loop: password2
// and password3 are always asked, then password4.. until an empty answer. Empty
// entries are dropped by the derivation (getValidPasswords), so they are kept
// for layout parity.
func collectDataCipherPipeOptionalPasswords(p *dataCipherPipeParams) error {
	for i := 2; i <= 3; i++ {
		extra, err := param.Password(i18n.TWithData("data_cipher.prompt.password_optional", map[string]interface{}{
			"N": i,
		}), i18n.T("data_cipher.prompt.password_optional_help"), param.WithoutRequired())
		if err != nil {
			return err
		}
		p.Extras = append(p.Extras, extra)
	}
	for len(p.Extras) < maxKeysCount {
		pwNum := len(p.Extras) + 2
		extra, err := param.Password(i18n.TWithData("data_cipher.prompt.password_optional", map[string]interface{}{
			"N": pwNum,
		}), i18n.T("data_cipher.prompt.password_optional_help"), param.WithoutRequired())
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(extra)) == 0 {
			clear(extra)
			break
		}
		p.Extras = append(p.Extras, extra)
	}
	return nil
}

// collectDataCipherPipePassword1 collects password1: encrypt offers the
// question-answer high-strength flow (declining falls back to a hidden prompt);
// decrypt re-answers stored questions or asks for a hidden password.
func collectDataCipherPipePassword1(salt string, allowQnA bool, hintIDs []string) ([]byte, []string, error) {
	if allowQnA {
		useQnA, err := param.Confirm(i18n.T("data_cipher.prompt.use_question_answer"), true)
		if err != nil {
			return nil, nil, err
		}
		if useQnA {
			return runQuestionAnswerFlowBytes(salt)
		}
	} else if len(hintIDs) > 0 {
		steps, err := buildRestoreSteps(hintIDs)
		if err != nil {
			return nil, nil, err
		}
		pw, err := runReanswerFlowBytes(steps, salt)
		if err != nil {
			return nil, nil, err
		}
		return pw, nil, nil
	}
	pw, err := param.Password(i18n.T("data_cipher.prompt.password1"), "")
	if err != nil {
		return nil, nil, err
	}
	return pw, nil, nil
}

// validateDataCipherPipeSecrets runs the web tool's keys[] rules on bytes: the
// 3 strong keys must be high-strength and password1 must satisfy the composite
// rule. No string copy of a secret is created.
func validateDataCipherPipeSecrets(p *dataCipherPipeParams) error {
	if len(p.Keys) < 3 || len(p.Password1) == 0 {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.password_required"))
	}
	for i := 0; i < 3; i++ {
		if !isHighStrengthBytes(trimASCIISpaceBytes(p.Keys[i])) {
			return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.key_not_high_strength", map[string]interface{}{
				"N": i + 1,
			}))
		}
	}
	if err := validatePasswordBytes(p.Password1); err != nil {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.password1_invalid"))
	}
	return nil
}

// resolveDataCipherPipeOutput resolves the output path: the provided value
// wins, otherwise the volatile mntemp default is used (prompted on a TTY).
func resolveDataCipherPipeOutput(message, provided, fallback string) (string, error) {
	if provided != "" {
		return provided, nil
	}
	def := mntempSaveDefault("data-cipher", fallback)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return def, nil
	}
	out, err := param.Input(message, def, "", param.WithoutRequired())
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return def, nil
	}
	return out, nil
}

// trimASCIISpaceBytes trims ASCII whitespace from both ends of b, mirroring
// strings.TrimSpace without allocating a string.
func trimASCIISpaceBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isASCIISpace(b[start]) {
		start++
	}
	for end > start && isASCIISpace(b[end-1]) {
		end--
	}
	return b[start:end]
}
