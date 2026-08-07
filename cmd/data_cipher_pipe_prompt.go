package cmd

// Interactive (TTY) helpers of data-cipher-pipe plus the shared secret
// resolution/validation used by the piped flow. The 3 strong keys can only be
// passed via the piped JSON; when stdin is a TTY (no pipe) the command refuses
// to run. Secrets are wipeable []byte.
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
)

// runDataCipherPipeInteractive is the TTY entry. The 3 strong keys can only be
// passed via the pipe, so a pure-TTY invocation has no key source and fails
// fast instead of collecting password1 first.
func runDataCipherPipeInteractive() error {
	return fmt.Errorf("%s", i18n.T("data_cipher.error.keys_pipe_required"))
}

// resolveDataCipherPipePasswords makes sure the 3 strong keys (which can only
// come from the pipe) and password1 are present. The keys are never collected
// interactively — a missing key set fails fast. password1 is reused when the
// piped JSON carried it, otherwise collected interactively (redirecting to
// /dev/tty when stdin is the consumed pipe).
func resolveDataCipherPipePasswords(p *dataCipherPipeParams, salt string, allowQnA bool, hintIDs []string) error {
	if len(p.Keys) < 3 {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.keys_pipe_required"))
	}
	if len(p.Password1) > 0 {
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

// collectDataCipherPipeMissingSecrets fills only the missing password1 (the
// keys are never collected here — they must have come from the pipe) and the
// optional extra password (collected on a TTY so decrypt matches whatever the
// encrypt run used; an empty answer means none).
func collectDataCipherPipeMissingSecrets(p *dataCipherPipeParams, salt string, allowQnA bool, hintIDs []string) error {
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

// collectDataCipherPipePassword1 collects password1: encrypt always runs the
// question-answer high-strength flow; decrypt re-answers the stored questions
// or asks for a hidden password when the bundle stored none.
func collectDataCipherPipePassword1(salt string, allowQnA bool, hintIDs []string) ([]byte, []string, error) {
	if len(hintIDs) > 0 {
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
	if allowQnA {
		return runQuestionAnswerFlowBytes(salt)
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
