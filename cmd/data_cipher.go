package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/safety"
)

// containerVersion mirrors the web tool's encrypted_data.version (10000).
const dataCipherContainerVersion = 10000

// maxInputSize is the web tool's file-size limit (512MB).
const maxInputSize = 512 * 1024 * 1024

// maxKeysCount mirrors the web tool's cap: 3 strong keys + 10 passwords (MAX_KEYS_COUNT).
const maxKeysCount = 3 + 10

var (
	dataCipherMode      string
	dataCipherInputType string
	dataCipherText      string
	dataCipherFile      string
	// dataCipherKeys holds the 3 strong keys from -k (web keys[0..2]).
	dataCipherKeys []string
	// dataCipherPassword is password1 from -p (web keys[3]).
	dataCipherPassword string
	// dataCipherExtraPassword is an optional extra password from
	// --extra-password, appended at the end of the key set (no strength rule).
	dataCipherExtraPassword string
	// dataCipherPasswords is the resolved full key/password list used by the
	// encrypt/decrypt pipeline (3 strong keys + password1 + optional extras).
	dataCipherPasswords []string
	dataCipherSalt      string
	dataCipherHint      string
	dataCipherOutput    string
	// dataCipherSelectedHints records the question-answer question IDs chosen for
	// password1 during encrypt, written into meta-data selectedHints so decrypt
	// can re-answer them and reproduce password1.
	dataCipherSelectedHints []string
)

var dataCipherCmd = &cobra.Command{
	Use:   "data-cipher [input file]",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDataCipher(args)
	},
}

// cipherInput holds the resolved input to encrypt/decrypt.
type cipherInput struct {
	inputType string // "text" or "file"
	data      []byte // raw bytes (UTF-8 for text, file content for file)
	fileName  string // original file name (file input only); empty for text
	mimeType  string // coarse MIME type (file input only); "text/plain" for text
}

// runDataCipher resolves parameters in order (mode → input-type → content),
// flag-first with interactive prompt fallback when a TTY is available, then
// dispatches to encrypt/decrypt.
//
//   - mode:        NO default; must be chosen (flag or interactive select)
//   - input-type:  encrypt allows text|file (default file); decrypt is file-only
//   - content:     --text / --file / positional arg, else interactive prompt
//
// Ordering matches the user's mental model (mode → input-type → content).
func runDataCipher(args []string) error {
	// 1. Resolve the mode first (NO default — encrypt and decrypt differ fundamentally).
	mode := dataCipherMode
	if mode == "" {
		if isStdinTerminal() {
			modeOpts := []struct {
				value string
				label string
			}{
				{"encrypt", i18n.T("data_cipher.option.encrypt")},
				{"decrypt", i18n.T("data_cipher.option.decrypt")},
			}
			modeLabels := make([]string, len(modeOpts))
			modeLabelToValue := make(map[string]string, len(modeOpts))
			for i, o := range modeOpts {
				modeLabels[i] = o.label
				modeLabelToValue[o.label] = o.value
			}
			chosen, err := param.Select(i18n.T("data_cipher.prompt.mode"), modeLabels, "", "")
			if err != nil {
				return err
			}
			mode = modeLabelToValue[chosen]
		} else {
			return fmt.Errorf("%s", i18n.T("data_cipher.error.mode_required"))
		}
	}
	if mode != "encrypt" && mode != "decrypt" {
		return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.invalid_mode", map[string]interface{}{
			"Mode": mode,
		}))
	}

	// 2. Resolve the input type. Decrypt is always file (web tool locks it too).
	inputType := dataCipherInputType
	if mode == "decrypt" {
		if inputType != "" && inputType != "file" {
			return fmt.Errorf("%s", i18n.T("data_cipher.error.decrypt_file_only"))
		}
		inputType = "file"
	} else if inputType == "" {
		// encrypt: default to file in non-interactive, prompt in TTY.
		if isStdinTerminal() {
			typeOpts := []struct {
				value string
				label string
			}{
				{"file", i18n.T("data_cipher.option.file")},
				{"text", i18n.T("data_cipher.option.text")},
			}
			typeLabels := make([]string, len(typeOpts))
			typeLabelToValue := make(map[string]string, len(typeOpts))
			for i, o := range typeOpts {
				typeLabels[i] = o.label
				typeLabelToValue[o.label] = o.value
			}
			chosen, err := param.Select(i18n.T("data_cipher.prompt.input_type"), typeLabels, "", "")
			if err != nil {
				return err
			}
			inputType = typeLabelToValue[chosen]
		} else {
			inputType = "file"
		}
	}
	if inputType != "text" && inputType != "file" {
		return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.invalid_input_type", map[string]interface{}{
			"Type": inputType,
		}))
	}

	// 3. Resolve the input content based on the (now-known) input type.
	// Positional arg acts as a shorthand for --file.
	positionalFile := ""
	if len(args) > 0 {
		positionalFile = args[0]
	}
	in, err := resolveCipherInput(inputType, positionalFile)
	if err != nil {
		return err
	}

	switch mode {
	case "encrypt":
		return runEncrypt(in)
	case "decrypt":
		return runDecrypt(in)
	default:
		return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.invalid_mode", map[string]interface{}{
			"Mode": mode,
		}))
	}
}

// resolveCipherInput builds the cipherInput from flags, positional arg, or an
// interactive prompt (TTY only). For text: --text or MultiInput. For file:
// --file / positional arg or Input, then read with the size limit.
func resolveCipherInput(inputType, positionalFile string) (*cipherInput, error) {
	in := &cipherInput{inputType: inputType}
	switch inputType {
	case "text":
		text := dataCipherText
		if text == "" {
			if !isStdinTerminal() {
				return nil, fmt.Errorf("%s", i18n.T("data_cipher.error.text_required"))
			}
			input, err := param.MultiInput(i18n.T("data_cipher.prompt.text"), "")
			if err != nil {
				return nil, err
			}
			text = input
		}
		if strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("%s", i18n.T("data_cipher.error.empty_input"))
		}
		in.data = []byte(text)
		in.mimeType = "text/plain"
	case "file":
		path := dataCipherFile
		if path == "" {
			path = positionalFile
		}
		if path == "" {
			if !isStdinTerminal() {
				return nil, fmt.Errorf("%s", i18n.T("data_cipher.error.input_required"))
			}
			p, err := param.Input(i18n.T("data_cipher.prompt.input"), "", "")
			if err != nil {
				return nil, err
			}
			path = p
		}
		data, err := readInputFile(path)
		if err != nil {
			return nil, err
		}
		in.data = data
		in.fileName = filepath.Base(path)
		in.mimeType = detectMimeType(path)
	}
	return in, nil
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		dataCipherCmd.Short = i18n.T("data_cipher.short")
		dataCipherCmd.Long = i18n.T("data_cipher.long")
	})
	dataCipherCmd.Flags().StringVar(&dataCipherMode, "mode", "", i18n.T("data_cipher.flag.mode"))
	dataCipherCmd.Flags().StringVar(&dataCipherInputType, "input-type", "", i18n.T("data_cipher.flag.input_type"))
	dataCipherCmd.Flags().StringVar(&dataCipherText, "text", "", i18n.T("data_cipher.flag.text"))
	dataCipherCmd.Flags().StringVar(&dataCipherFile, "file", "", i18n.T("data_cipher.flag.file"))
	// StringArray (not StringSlice) so a value containing a comma is kept
	// whole: the strong-key / generated-password charset includes ",".
	dataCipherCmd.Flags().StringArrayVarP(&dataCipherKeys, "key", "k", nil, i18n.T("data_cipher.flag.key"))
	dataCipherCmd.Flags().StringVarP(&dataCipherPassword, "password", "p", "", i18n.T("data_cipher.flag.password"))
	dataCipherCmd.Flags().StringVar(&dataCipherExtraPassword, "extra-password", "", i18n.T("data_cipher.flag.extra_password"))
	dataCipherCmd.Flags().StringVar(&dataCipherSalt, "salt", "", i18n.T("data_cipher.flag.salt"))
	dataCipherCmd.Flags().StringVar(&dataCipherHint, "hint", "", i18n.T("data_cipher.flag.hint"))
	dataCipherCmd.Flags().StringVarP(&dataCipherOutput, "output", "o", "", i18n.T("data_cipher.flag.output"))
	rootCmd.AddCommand(dataCipherCmd)
}

// runEncrypt mirrors DataEncryptionForm.performEncryption + downloadResult(encrypt).
func runEncrypt(in *cipherInput) error {
	// Salt is resolved up front so a question-answer generated password1
	// (collected in resolvePasswords) and the encryption share the same salt;
	// otherwise decryption could not reproduce password1.
	if dataCipherSalt == "" {
		dataCipherSalt = safety.BytesToHex(safety.GenerateRandomBytes(64))
	}
	if _, err := hex.DecodeString(dataCipherSalt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.salt_hex"), err)
	}

	// Hint is collected BEFORE passwords: it belongs to the "data input" section
	// alongside the text/file content, which precedes the key config in the web
	// form. So order is: content -> hint -> passwords -> output.
	if err := resolveHint(); err != nil {
		return err
	}
	if err := resolvePasswords(true, dataCipherSalt, nil); err != nil {
		return err
	}
	// validateKeys covers the -k/-p/--extra-password flag path (the interactive
	// path was validated live).
	if err := validateKeys(); err != nil {
		return err
	}
	if err := resolveOutputPath(
		i18n.T("data_cipher.prompt.output_encrypt"),
		fmt.Sprintf("encrypted-%d.zip", time.Now().UnixMilli()),
	); err != nil {
		return err
	}
	data := in.data
	salt := dataCipherSalt

	// 1. AES-256-GCM encrypt with ALL keys.
	ct, err := aesgcm.EncryptWithPassword(data, salt, dataCipherPasswords)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}

	// 2. Assemble the binary container (76B header + ciphertext).
	bin, err := container.AssembleDownloadData(dataCipherContainerVersion, 0, salt, ct)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}

	// 3. assemble_package_key (first three strong keys only) for integrityHash.
	assembleKey, err := safety.AssemblePackageKey(dataCipherPasswords, salt)
	if err != nil {
		return err
	}

	// 4. meta-data.json with dual HMAC signatures. selectedHints carries the
	// question-answer question IDs chosen for password1 (if any) so decrypt can
	// re-answer them and reproduce the password.
	selectedHints := dataCipherSelectedHints
	if selectedHints == nil {
		selectedHints = []string{}
	}
	meta := &container.MetaData{
		Version:       dataCipherContainerVersion,
		Salt:          salt,
		FileName:      in.fileName,
		FileType:      in.mimeType,
		Hint:          dataCipherHint,
		SelectedHints: selectedHints,
		SHA256:        safety.SHA256Hex(string(bin)),
		CreatedAt:     time.Now().UnixMilli(),
	}
	meta.SignMetaData(assembleKey)
	metaJSON, err := container.MarshalMetaData(meta)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}

	// 5. Zip {encrypted-data.bin, meta-data.json}.
	zipData, err := container.CompressBundle(container.BundleEntries{Bin: bin, Meta: metaJSON})
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}

	// outPath was resolved up-front by resolveOutputPath (--output > TTY prompt > default).
	if err := os.WriteFile(dataCipherOutput, zipData, 0o644); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.write_output"), err)
	}
	fmt.Println(i18n.TWithData("data_cipher.output.encrypt_success", map[string]interface{}{
		"Size": len(data),
		"Path": dataCipherOutput,
	}))
	if isVolatilePath(dataCipherOutput) {
		fmt.Println(i18n.T("data_cipher.output.volatile_reminder"))
	}
	return nil
}

// runDecrypt mirrors DataEncryptionForm.validateAndParseBundle + performDecryption.
func runDecrypt(in *cipherInput) error {
	zipData := in.data

	// 1. Decompress zip -> {bin, meta}. Done before passwords so the stored
	// hint can be shown before the user is asked for the keys.
	entries, err := container.DecompressBundle(zipData)
	if err != nil {
		return err
	}

	// 2. Parse meta-data.json + validate fields.
	meta, err := container.ParseMetaData(entries.Meta)
	if err != nil {
		return err
	}
	if err := meta.ValidateMetaDataFields(); err != nil {
		return err
	}

	// 3. SHA-256 integrity check on the .bin.
	actual := safety.SHA256Hex(string(entries.Bin))
	if actual != meta.SHA256 {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.sha256_mismatch"))
	}

	// 4. metaHash weak check (key=salt).
	if !meta.VerifyMetaHash() {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.meta_tampered"))
	}

	// 5. Parse the binary container up front: the salt_seed it embeds is needed
	// both for the key derivation and to re-answer the stored question-answer
	// questions for password1 (selectedHints). This is a structural parse only;
	// the GCM decrypt still happens after the keys are resolved.
	parsed, err := container.ExtractDecryptedData(entries.Bin)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.parse_container"), err)
	}
	decryptSalt := parsed.SaltSeed

	// 6. Show the hint stored during encryption so the user can recall the
	// original input text and password.
	if meta.Hint != "" {
		fmt.Println(i18n.TWithData("data_cipher.output.decrypt_hint", map[string]interface{}{
			"Hint": meta.Hint,
		}))
	}

	// 7. resolvePasswords(false): decrypt never generates a new high-strength
	// password1; when the file's selectedHints are non-empty, password1 is
	// reproduced by re-answering those questions with the bin's salt_seed
	// (mirrors key-derive restore), otherwise it is typed directly.
	if err := resolvePasswords(false, parsed.SaltSeed, meta.SelectedHints); err != nil {
		return err
	}
	// validateKeys covers the -k/-p/--extra-password flag path (interactive path
	// was validated live).
	// The web tool validates the form before decrypting too; a weak key/password
	// here means the keys[] are malformed, so decryption would never succeed.
	if err := validateKeys(); err != nil {
		return err
	}

	// 8. integrityHash strong check + tamper trap.
	// NOTE: the assemble_package_key is derived from the bin's salt_seed
	// (parsed.SaltSeed), matching the web tool which uses salt.value set from
	// extractSaltFromEncryptedData — NOT meta.Salt. For a valid file both are
	// identical (the encryptor writes the same salt into both); for a tampered
	// meta.salt the metaHash check above already rejects the file.
	assembleKey, err := safety.AssemblePackageKey(dataCipherPasswords, parsed.SaltSeed)
	if err != nil {
		return err
	}
	storedIntegrity := meta.IntegrityHash
	if !meta.VerifyIntegrityHash(assembleKey) {
		// Tamper trap: silently poison the salt so GCM auth fails, hiding that
		// tampering was detected (mirrors web: hmac_hash(salt, integrityHash)).
		decryptSalt = safety.HMACSHA3512([]byte(decryptSalt), []byte(storedIntegrity))
	}

	// 9. AES-256-GCM decrypt with all keys.
	pt, err := aesgcm.DecryptWithPassword(parsed.EncryptedData, decryptSalt, dataCipherPasswords)
	if err != nil {
		return fmt.Errorf("%s: %s", i18n.T("data_cipher.error.decrypt_failed"), strings.TrimRight(err.Error(), "!"))
	}

	// 10. Write restored file (prefer original Name from meta-data).
	outPath := dataCipherOutput
	if outPath == "" {
		base := "decrypted.txt"
		if meta.FileName != "" {
			base = "decrypted-" + meta.FileName
		}
		if err := resolveOutputPath(i18n.T("data_cipher.prompt.output_decrypt"), base); err != nil {
			return err
		}
		outPath = dataCipherOutput
	}
	if err := os.WriteFile(outPath, pt, 0o644); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.write_output"), err)
	}
	fmt.Println(i18n.TWithData("data_cipher.output.decrypt_success", map[string]interface{}{
		"Size": len(pt),
		"Path": outPath,
	}))
	return nil
}

// resolvePasswords assembles the resolved dataCipherPasswords list from the
// flag sources and, when needed, interactive prompts.
//
// Layout mirrors the web tool's keys[]:
//
//	keys[0..2] = 3 strong keys (-k, key-derive output, 128-hex each)
//	keys[3]    = password1 (-p)
//	keys[4..]  = optional additional passwords (interactive slots, then the
//	             --extra-password value appended at the end)
//
// Required entries (the 3 strong keys and password1) come from flags when
// supplied; otherwise they are collected interactively when a TTY is available,
// and the command fails when they are missing in a non-interactive run. The
// optional additional passwords are ALWAYS asked in a TTY (even when
// --extra-password was supplied) — --extra-password is appended at the end; the
// derivation is order-independent, so its position does not affect the key.
//
// allowQnA: encrypt=true enables the question-answer high-strength generation for
// password1; decrypt=false reproduces the original password instead — typed
// directly, or re-answered from the stored selectedHints when present. salt is
// the salt shared with the QnA password (encrypt: resolved salt; decrypt: the
// bin's salt_seed). hintIDs are the selectedHints from the file (decrypt only).
func resolvePasswords(allowQnA bool, salt string, hintIDs []string) error {
	if len(dataCipherKeys) > 3 {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.too_many_keys"))
	}

	resolved := make([]string, 0, 3+1+1)

	// 1. Strong keys (web keys[0..2]) from -k; missing ones prompted in a TTY.
	resolved = append(resolved, dataCipherKeys...)
	if len(resolved) < 3 {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("data_cipher.error.password_required"))
		}
		for i := len(resolved); i < 3; i++ {
			keyNum := i + 1
			v, err := param.Password(i18n.TWithData("data_cipher.prompt.key_n", map[string]interface{}{
				"N": keyNum,
			}), i18n.T("data_cipher.prompt.key_help"), param.WithValidator(highStrengthKeyValidator(keyNum)))
			if err != nil {
				return err
			}
			resolved = append(resolved, v)
		}
	}

	// 2. password1 (web keys[3]) from -p, or interactively in a TTY (encrypt may
	// generate it via the question-answer flow; decrypt reproduces it from
	// selectedHints or asks directly).
	if dataCipherPassword != "" {
		resolved = append(resolved, dataCipherPassword)
	} else if !isStdinTerminal() {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.password_required"))
	} else {
		pw1, ids, err := promptPassword1(salt, allowQnA, hintIDs)
		if err != nil {
			return err
		}
		dataCipherSelectedHints = ids
		resolved = append(resolved, pw1)
	}

	// 3. Optional additional passwords (web keys[4..]) are always asked in a TTY
	// (empty answers are valid and dropped by the derivation). Non-interactive
	// runs get none of them. The collection stops one short of the web cap when
	// --extra-password is present so it can still be appended without exceeding
	// the 3+10 key limit.
	if isStdinTerminal() {
		extraReserved := 0
		if dataCipherExtraPassword != "" {
			extraReserved = 1
		}
		for i := 2; i <= 3; i++ { // i = password number (2, 3)
			extra, err := param.Input(i18n.TWithData("data_cipher.prompt.password_optional", map[string]interface{}{
				"N": i,
			}), "", i18n.T("data_cipher.prompt.password_optional_help"), param.WithoutRequired())
			if err != nil {
				return err
			}
			resolved = append(resolved, extra)
		}
		for len(resolved) < maxKeysCount-extraReserved {
			pwNum := len(resolved) - 2 // index 6 -> password4
			extra, err := param.Input(i18n.TWithData("data_cipher.prompt.password_optional", map[string]interface{}{
				"N": pwNum,
			}), "", i18n.T("data_cipher.prompt.password_optional_help"), param.WithoutRequired())
			if err != nil {
				return err
			}
			if strings.TrimSpace(extra) == "" {
				break
			}
			resolved = append(resolved, extra)
		}
	}

	// 4. --extra-password is appended at the end; the derivation is
	// order-independent, so its position does not affect the derived key.
	if dataCipherExtraPassword != "" {
		resolved = append(resolved, dataCipherExtraPassword)
	}

	dataCipherPasswords = resolved
	return nil
}

// promptPassword1 collects password1 and returns it plus the chosen
// question-answer question IDs (encrypt only; nil otherwise).
//
//   - encrypt: offers the question-answer high-strength generation (same flow as
//     key-derive); declining falls back to the plain hidden prompt with the web
//     tool's composite password1 rule.
//   - decrypt: when the file's selectedHints are non-empty, password1 is
//     reproduced by re-answering those questions with the bin's salt_seed
//     (mirrors key-derive restore); otherwise the plain hidden prompt is used.
func promptPassword1(salt string, encrypt bool, hintIDs []string) (string, []string, error) {
	if encrypt {
		useQnA, err := param.Confirm(i18n.T("data_cipher.prompt.use_question_answer"), true)
		if err != nil {
			return "", nil, err
		}
		if useQnA {
			pw, ids, err := runQuestionAnswerFlow(salt)
			if err != nil {
				return "", nil, err
			}
			return pw, ids, nil
		}
	} else if len(hintIDs) > 0 {
		steps, err := buildRestoreSteps(hintIDs)
		if err != nil {
			return "", nil, err
		}
		pw, err := runReanswerFlow(steps, salt)
		if err != nil {
			return "", nil, err
		}
		return pw, nil, nil
	}
	pw, err := param.Password(i18n.T("data_cipher.prompt.password1"), "", param.WithValidator(password1Validator))
	if err != nil {
		return "", nil, err
	}
	return pw, nil, nil
}

// resolveHint collects the optional hint interactively BEFORE passwords.
// Flag-first (--hint wins); otherwise a TTY is prompted with MultiInput.
// The hint is optional, so an empty answer is valid in both flows. Non-interactive
// runs without --hint simply leave the hint empty (matches the web tool's default).
//
// Ordering matches the web tool's form: the hint belongs to the "data input"
// section, which precedes the key config. At the CLI the content is collected
// first (resolveCipherInput in runDataCipher), then the hint (here), then
// passwords (resolvePasswords).
func resolveHint() error {
	if dataCipherHint != "" {
		return nil // already supplied via --hint
	}
	if !isStdinTerminal() {
		return nil // non-interactive: hint stays empty, that's fine
	}
	hint, err := param.MultiInput(i18n.T("data_cipher.prompt.hint"), i18n.T("data_cipher.prompt.hint_help"), param.WithoutRequired())
	if err != nil {
		return err
	}
	dataCipherHint = strings.TrimSpace(hint)
	return nil
}

// highStrengthKeyValidator returns a validator enforcing the web tool's
// strong-key rule (DataEncryptionForm.vue:744-746: IsPasswordHighStrength) for
// key N (1-indexed). The web tool trims before validating, so we do too.
func highStrengthKeyValidator(keyNum int) func(string) error {
	return func(s string) error {
		if safety.IsPasswordHighStrength(strings.TrimSpace(s)) {
			return nil
		}
		return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.key_not_high_strength", map[string]interface{}{
			"N": keyNum,
		}))
	}
}

// password1Validator enforces the web tool's password1 composite rule
// (DataEncryptionForm.vue:756-758: isPassword1Valid). The web tool trims before
// validating, so we do too.
func password1Validator(s string) error {
	if safety.IsPassword1Valid(strings.TrimSpace(s)) {
		return nil
	}
	return fmt.Errorf("%s", i18n.T("data_cipher.error.password1_invalid"))
}

// validateKeys runs the web tool's full keys[] validation
// (DataEncryptionForm.vue:772-784 validateForm → validateKey) against the
// resolved dataCipherPasswords. It covers BOTH flows: the interactive path
// (already validated live above) and the -k/-p/--extra-password flag path
// (which bypasses the live validators). Rules, mirroring the web tool exactly:
//
//	keys[0..2] (key1/2/3):   non-empty + IsPasswordHighStrength
//	keys[3]    (password1):  non-empty + IsPassword1Valid
//	keys[4..]  (password2/3..): not validated (web: errors.value.keys[..] = "")
//
// This guarantees the CLI never produces a file the web tool would refuse to
// encrypt, regardless of how the passwords were supplied.
func validateKeys() error {
	if len(dataCipherPasswords) < 4 {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.password_required"))
	}
	for i := 0; i < 3; i++ {
		v := strings.TrimSpace(dataCipherPasswords[i])
		if !safety.IsPasswordHighStrength(v) {
			return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.key_not_high_strength", map[string]interface{}{
				"N": i + 1,
			}))
		}
	}
	if !safety.IsPassword1Valid(strings.TrimSpace(dataCipherPasswords[3])) {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.password1_invalid"))
	}
	return nil
}

// resolveOutputPath resolves the output path when -o/--output was not given.
// The default shown is the caller-provided fallback (encrypt: timestamped zip;
// decrypt: decrypted-<originalname>), pointing into the volatile mntemp
// filesystem via mntempSaveDefault so nothing sensitive persists on disk. In a
// non-interactive run the fallback is applied silently — matches key_derive's
// behaviour where the default is used without prompting.
func resolveOutputPath(message, fallback string) error {
	if dataCipherOutput != "" {
		return nil // already supplied via -o/--output
	}
	if !isStdinTerminal() {
		dataCipherOutput = fallback
		return nil
	}
	def := mntempSaveDefault("data-cipher", fallback)
	out, err := param.Input(message, def, "", param.WithoutRequired())
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		out = def
	}
	dataCipherOutput = out
	return nil
}

// readInputFile reads the input with the 512MB limit enforced.
func readInputFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("data_cipher.error.read_input"), err)
	}
	if info.Size() > maxInputSize {
		return nil, fmt.Errorf("%s", i18n.T("data_cipher.error.file_too_large"))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("data_cipher.error.read_input"), err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("data_cipher.error.empty_input"))
	}
	return data, nil
}

// detectMimeType returns a coarse MIME type by extension for meta-data.fileType.
func detectMimeType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".zip":
		return "application/zip"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}
