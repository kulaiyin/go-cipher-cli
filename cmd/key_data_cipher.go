package cmd

// key-data-cipher combines key derivation (key-derive-pipe) with data
// encryption (data-cipher-pipe): it restores the 3 strong keys from a recovery
// config (key-derive.txt) or derives a fresh key set via the question-answer
// flow, then encrypts or decrypts a bundle. The keys are never entered by hand
// and never carried in argv — they stay wipeable []byte end to end.
//
// Encrypt: a config path (JSON "config") restores the existing key set; without
// one the command derives a fresh key set via the question-answer flow and
// writes a new recovery config to the volatile mntemp directory.
//
// Decrypt: the recovery config AND the encrypted bundle must both exist; the
// keys are restored from the config, then the bundle is decrypted.

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/util"
	"go-cipher-cli/internal/validation"
)

// keyDataCipherParams carries the combined command's inputs: the recovery
// config path plus the data-cipher parameter set (content, secrets, output).
type keyDataCipherParams struct {
	Config string
	Pipe   dataCipherPipeParams
}

// keyDataCipherCmd takes NO flags: every parameter arrives as a JSON object on
// stdin (or via interactive prompts on a TTY). The keys are always derived
// in-process from the recovery config or the question-answer flow.
var keyDataCipherCmd = &cobra.Command{
	Use:          "key-data-cipher",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return runKeyDataCipherInteractive()
		}
		return runKeyDataCipherPipe()
	},
}

// runKeyDataCipherInteractive collects mode and the mode-specific inputs on a
// TTY, then dispatches to the shared encrypt/decrypt flows. stdin is already a
// terminal, so no /dev/tty redirect is needed.
func runKeyDataCipherInteractive() error {
	mode, err := pipeSelectLabeled(i18n.T("data_cipher.prompt.mode"), []labelValue{
		{i18n.T("data_cipher.option.encrypt"), "encrypt"},
		{i18n.T("data_cipher.option.decrypt"), "decrypt"},
	}, "", "")
	if err != nil {
		return err
	}
	p := &keyDataCipherParams{Pipe: dataCipherPipeParams{Mode: mode}}

	if mode == "decrypt" {
		if err := collectKeyDataCipherDecryptInputs(p); err != nil {
			return err
		}
		return runKeyDataCipherDecrypt(p)
	}
	if err := collectKeyDataCipherEncryptInputs(p); err != nil {
		return err
	}
	return runKeyDataCipherEncrypt(p)
}

// runKeyDataCipherPipe parses the piped JSON object and dispatches. Secrets are
// collected interactively via /dev/tty when the JSON omits them. The pipe-entry
// wipe covers secrets parsed from JSON (or rejected by validation); the
// per-mode runKeyDataCipher{Encrypt,Decrypt} also defer a wipe for the keys
// they derive (the only wipe on the interactive path). Both defers run on the
// pipe path and are idempotent.
func runKeyDataCipherPipe() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	defer util.WipeBytes(data)

	p, err := parseKeyDataCipherJSON(data)
	if err != nil {
		return err
	}
	defer wipeDataCipherPipeSecrets(&p.Pipe)

	if err := validateKeyDataCipherFields(&p); err != nil {
		return err
	}

	if p.Pipe.Mode == "decrypt" {
		if err := keyDataCipherCheckDecryptFiles(&p); err != nil {
			return err
		}
		return keyDataCipherWithTTY(func() error { return runKeyDataCipherDecrypt(&p) })
	}
	return keyDataCipherWithTTY(func() error { return runKeyDataCipherEncrypt(&p) })
}

// parseKeyDataCipherJSON parses the stdin JSON into the combined params,
// reusing data-cipher's field parser for the shared fields and reading the
// recovery config path separately.
func parseKeyDataCipherJSON(data []byte) (keyDataCipherParams, error) {
	pipe, err := parseDataCipherPipeJSON(data)
	if err != nil {
		return keyDataCipherParams{}, err
	}
	p := keyDataCipherParams{Pipe: pipe}
	if v, err := jsonparser.GetString(data, "config"); err == nil {
		p.Config = strings.TrimSpace(v)
	}
	return p, nil
}

// validateKeyDataCipherFields runs data-cipher's non-secret field checks
// (mode, input-type, content) and rejects external keys/password1: this command
// derives the keys in-process and collects password1 via the question-answer
// high-strength flow, so a piped keys[]/password1 would be silently overwritten
// (and never wiped) — fail fast and wipe the leaked copies instead.
// extraPasswords ARE allowed via the pipe, matching data-cipher-pipe, since they
// are optional additions (web keys[4..]) that do not override the derived keys.
func validateKeyDataCipherFields(p *keyDataCipherParams) error {
	if err := validateDataCipherPipeNonSecretFields(&p.Pipe); err != nil {
		return err
	}
	if len(p.Pipe.Keys) > 0 || len(p.Pipe.Password1) > 0 {
		for _, k := range p.Pipe.Keys {
			util.WipeBytes(k)
		}
		util.WipeBytes(p.Pipe.Password1)
		p.Pipe.Keys = nil
		p.Pipe.Password1 = nil
		return fmt.Errorf("%s", i18n.T("key_data_cipher.error.keys_not_allowed"))
	}
	return nil
}

// collectKeyDataCipherDecryptInputs prompts for the recovery config path and
// the encrypted bundle path, then confirms both files exist before decrypting.
func collectKeyDataCipherDecryptInputs(p *keyDataCipherParams) error {
	cfg, err := param.Input(i18n.T("key_derive.prompt.config"), "", i18n.T("key_derive.prompt.config_help"))
	if err != nil {
		return err
	}
	p.Config = strings.TrimSpace(cfg)
	file, err := param.Input(i18n.T("data_cipher.prompt.input"), "", "")
	if err != nil {
		return err
	}
	p.Pipe.File = strings.TrimSpace(file)
	return keyDataCipherCheckDecryptFiles(p)
}

// collectKeyDataCipherEncryptInputs prompts for the key source (an optional
// recovery config path), then input type, content, and hint. A config path
// restores the existing key set; an empty answer derives a fresh key set.
func collectKeyDataCipherEncryptInputs(p *keyDataCipherParams) error {
	cfg, err := param.Input(i18n.T("key_derive.prompt.config"), "", i18n.T("key_data_cipher.prompt.config_help_encrypt"), param.WithoutRequired())
	if err != nil {
		return err
	}
	p.Config = strings.TrimSpace(cfg)
	if p.Config != "" {
		if err := checkConfigExists(p.Config); err != nil {
			return err
		}
	}

	it, err := pipeSelectLabeled(i18n.T("data_cipher.prompt.input_type"), []labelValue{
		{i18n.T("data_cipher.option.file"), "file"},
		{i18n.T("data_cipher.option.text"), "text"},
	}, "", "")
	if err != nil {
		return err
	}
	p.Pipe.InputType = it
	if it == "text" {
		text, err := param.MultiInput(i18n.T("data_cipher.prompt.text"), "")
		if err != nil {
			return err
		}
		p.Pipe.Text = text
	} else {
		path, err := param.Input(i18n.T("data_cipher.prompt.input"), "", "")
		if err != nil {
			return err
		}
		p.Pipe.File = path
	}
	hint, err := param.MultiInput(i18n.T("data_cipher.prompt.hint"), i18n.T("data_cipher.prompt.hint_help"), param.WithoutRequired())
	if err != nil {
		return err
	}
	p.Pipe.Hint = strings.TrimSpace(hint)
	return nil
}

// checkConfigExists returns a "config not found" error when the recovery config
// path does not resolve. Centralized so the message has a single source.
func checkConfigExists(cfgPath string) error {
	if _, err := os.Stat(cfgPath); err != nil {
		return fmt.Errorf("%s", i18n.TWithData("key_data_cipher.error.config_not_found", map[string]interface{}{
			"Path": cfgPath,
		}))
	}
	return nil
}

// keyDataCipherCheckDecryptFiles confirms both the recovery config and the
// encrypted bundle exist before any decryption work is attempted.
func keyDataCipherCheckDecryptFiles(p *keyDataCipherParams) error {
	if p.Config == "" {
		return fmt.Errorf("%s", i18n.T("key_data_cipher.error.config_required"))
	}
	if p.Pipe.File == "" {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.input_required"))
	}
	if err := checkConfigExists(p.Config); err != nil {
		return err
	}
	if _, err := os.Stat(p.Pipe.File); err != nil {
		return fmt.Errorf("%s", i18n.TWithData("key_data_cipher.error.input_not_found", map[string]interface{}{
			"Path": p.Pipe.File,
		}))
	}
	return nil
}

// keyDataCipherWithTTY runs fn with stdin redirected to /dev/tty when the real
// stdin is a consumed pipe, so the interactive prompts can run. On a TTY it
// runs fn directly.
func keyDataCipherWithTTY(fn func() error) error {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return fn()
	}
	restore, err := redirectStdinToTTY()
	if err != nil {
		return err
	}
	defer restore()
	return fn()
}

// runKeyDataCipherEncrypt derives the key set (restore from config when given,
// otherwise a fresh question-answer generation) and delegates the encryption.
func runKeyDataCipherEncrypt(p *keyDataCipherParams) error {
	var keys [][]byte
	var err error
	if p.Config != "" {
		if err := checkConfigExists(p.Config); err != nil {
			return err
		}
		keys, err = deriveKeyDataCipherRestore(p.Config)
	} else {
		keys, err = deriveKeyDataCipherGenerate()
	}
	if err != nil {
		return err
	}
	p.Pipe.Keys = keys
	defer wipeDataCipherPipeSecrets(&p.Pipe)
	fmt.Println(i18n.T("key_data_cipher.stage.password1"))
	return runDataCipherPipeEncrypt(&p.Pipe)
}

// runKeyDataCipherDecrypt restores the key set from the recovery config and
// delegates the decryption.
func runKeyDataCipherDecrypt(p *keyDataCipherParams) error {
	keys, err := deriveKeyDataCipherRestore(p.Config)
	if err != nil {
		return err
	}
	p.Pipe.Keys = keys
	defer wipeDataCipherPipeSecrets(&p.Pipe)
	return runDataCipherPipeDecrypt(&p.Pipe)
}

// deriveKeyDataCipherRestore re-derives the key set from a recovery config: it
// collects the key-derive input, re-answers the stored questions (or asks for a
// hidden password when the config stored none), derives, and verifies the
// fingerprints. The derived raw keys are returned for the caller to wipe.
func deriveKeyDataCipherRestore(cfgPath string) ([][]byte, error) {
	cfg, err := loadRecoveryConfig(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_read_failed"), err)
	}
	if cfg.Salt == "" {
		return nil, fmt.Errorf("%s", i18n.T("key_derive.error.config_missing_salt"))
	}

	input, err := param.MultiInput(i18n.T("key_derive.prompt.input"), i18n.T("key_derive.prompt.input_help"), param.WithValidator(validation.ValidateKeyDeriveInput))
	if err != nil {
		return nil, err
	}
	input = cleanKeyDeriveText(input)

	var pw []byte
	if len(cfg.HintIDs) > 0 {
		steps, err := buildRestoreSteps(cfg.HintIDs)
		if err != nil {
			return nil, err
		}
		pw, err = runReanswerFlowBytes(steps, cfg.Salt)
		if err != nil {
			return nil, err
		}
	} else {
		pw, err = param.Password(i18n.T("key_derive.prompt.password"), "")
		if err != nil {
			return nil, err
		}
	}
	defer util.WipeBytes(pw)

	result := kdf.DeriveKeySetBytes(input, pw, cfg.Salt, kdf.Strength(cfg.Strength))
	if !result.Success {
		return nil, fmt.Errorf("%s: %s", i18n.T("key_derive.error.derive_failed"), result.Error)
	}
	matched := false
	for _, raw := range result.RawKeys {
		if kdf.ValidateKeyRecoveryBytes(raw, cfg.UUIDs) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%s", i18n.T("key_derive.output.restore_failed"))
	}
	return keySetToHexKeys(result.RawKeys), nil
}

// deriveKeyDataCipherGenerate derives a fresh key set via the question-answer
// flow and writes a new recovery config to the volatile mntemp directory so the
// keys can be restored later. The derived raw keys are returned for the caller
// to wipe.
func deriveKeyDataCipherGenerate() ([][]byte, error) {
	input, err := param.MultiInput(i18n.T("key_derive.prompt.input"), i18n.T("key_derive.prompt.input_help"), param.WithValidator(validation.ValidateKeyDeriveInput))
	if err != nil {
		return nil, err
	}
	input = cleanKeyDeriveText(input)

	strength, err := pipeSelectLabeled(i18n.T("key_derive.prompt.strength"), []labelValue{
		{i18n.T("key_derive.option.strength.basic"), "basic"},
		{i18n.T("key_derive.option.strength.medium"), "medium"},
		{i18n.T("key_derive.option.strength.advanced"), "advanced"},
	}, i18n.T("key_derive.option.strength.medium"), "")
	if err != nil {
		return nil, err
	}

	salt := kdf.GenerateSalt(64)
	fmt.Println(i18n.T("key_data_cipher.stage.derive_keys"))
	pw, ids, err := runQuestionAnswerFlowBytes(salt)
	if err != nil {
		return nil, err
	}
	defer util.WipeBytes(pw)

	result := kdf.DeriveKeySetBytes(input, pw, salt, kdf.Strength(strength))
	if !result.Success {
		return nil, fmt.Errorf("%s: %s", i18n.T("key_derive.error.derive_failed"), result.Error)
	}

	rc := buildPipeRecoveryConfig(result, "", ids)
	configText := formatFrontendRecoveryConfigBytes(rc, result.RawKeys, result.RawUUID)
	defer util.WipeBytes(configText)
	util.WipeBytes(result.RawUUID)

	path := mntempSaveDefault("key-data-cipher", "key-derive.txt")
	if err := os.WriteFile(path, configText, 0o600); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("key_derive.error.write_output_failed"), err)
	}
	fmt.Println(i18n.TWithData("key_data_cipher.output.config_written", map[string]interface{}{
		"Path": path,
	}))
	if isVolatilePath(path) {
		fmt.Println(i18n.T("key_data_cipher.output.config_volatile"))
	}

	return keySetToHexKeys(result.RawKeys), nil
}

// keySetToHexKeys encodes each raw key (64 bytes) into its 128-char lowercase
// hex form, which is the format the data-cipher pipeline expects in keys[]: the
// aesgcm layer treats a 128-hex value as a strong passthrough key, while a raw
// 64-byte value would be mistaken for a weak password and re-strengthened via
// argon2id, breaking byte-level compatibility with key-derive-pipe / the web
// tool. The raw key material is wiped after encoding so only the hex copies
// remain (and those are wiped by the caller via wipeDataCipherPipeSecrets).
func keySetToHexKeys(rawKeys [][]byte) [][]byte {
	hexKeys := make([][]byte, len(rawKeys))
	for i, raw := range rawKeys {
		h := make([]byte, hex.EncodedLen(len(raw)))
		hex.Encode(h, raw)
		hexKeys[i] = h
		util.WipeBytes(raw)
	}
	return hexKeys
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		keyDataCipherCmd.Short = i18n.T("key_data_cipher.short")
		keyDataCipherCmd.Long = i18n.T("key_data_cipher.long")
	})
	rootCmd.AddCommand(keyDataCipherCmd)
}
