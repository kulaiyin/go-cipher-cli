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
	dataCipherPasswords []string
	dataCipherSalt      string
	dataCipherHint      string
	dataCipherOutput    string
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
	dataCipherCmd.Flags().StringSliceVarP(&dataCipherPasswords, "password", "p", nil, i18n.T("data_cipher.flag.password"))
	dataCipherCmd.Flags().StringVar(&dataCipherSalt, "salt", "", i18n.T("data_cipher.flag.salt"))
	dataCipherCmd.Flags().StringVar(&dataCipherHint, "hint", "", i18n.T("data_cipher.flag.hint"))
	dataCipherCmd.Flags().StringVarP(&dataCipherOutput, "output", "o", "", i18n.T("data_cipher.flag.output"))
	rootCmd.AddCommand(dataCipherCmd)
}

// runEncrypt mirrors DataEncryptionForm.performEncryption + downloadResult(encrypt).
func runEncrypt(in *cipherInput) error {
	// Hint is collected BEFORE passwords: it belongs to the "data input" section
	// alongside the text/file content, which precedes the key config in the web
	// form. So order is: content -> hint -> passwords -> output.
	if err := resolveHint(); err != nil {
		return err
	}
	if err := resolvePasswords(); err != nil {
		return err
	}
	// validateKeys covers the -p flag path (interactive path was validated live).
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

	// Salt: use --salt or generate a 64-byte (128-hex) seed.
	salt := dataCipherSalt
	if salt == "" {
		salt = safety.BytesToHex(safety.GenerateRandomBytes(64))
	}
	if _, err := hex.DecodeString(salt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.salt_hex"), err)
	}

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

	// 4. meta-data.json with dual HMAC signatures.
	meta := &container.MetaData{
		Version:       dataCipherContainerVersion,
		Salt:          salt,
		FileName:      in.fileName,
		FileType:      in.mimeType,
		Hint:          dataCipherHint,
		SelectedHints: []string{},
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

	// 5. Show the hint stored during encryption so the user can recall the
	// original input text and password.
	if meta.Hint != "" {
		fmt.Println(i18n.TWithData("data_cipher.output.decrypt_hint", map[string]interface{}{
			"Hint": meta.Hint,
		}))
	}

	if err := resolvePasswords(); err != nil {
		return err
	}
	// validateKeys covers the -p flag path (interactive path was validated live).
	// The web tool validates the form before decrypting too; a weak key/password
	// here means the keys[] are malformed, so decryption would never succeed.
	if err := validateKeys(); err != nil {
		return err
	}

	// 6. Parse the binary container.
	parsed, err := container.ExtractDecryptedData(entries.Bin)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.parse_container"), err)
	}
	decryptSalt := parsed.SaltSeed

	// 7. integrityHash strong check + tamper trap.
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

	// 8. AES-256-GCM decrypt with all keys.
	pt, err := aesgcm.DecryptWithPassword(parsed.EncryptedData, decryptSalt, dataCipherPasswords)
	if err != nil {
		return fmt.Errorf("%s: %s", i18n.T("data_cipher.error.decrypt_failed"), strings.TrimRight(err.Error(), "!"))
	}

	// 9. Write restored file (prefer original Name from meta-data).
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

// resolvePasswords ensures the web tool's minimum (3 strong keys + password1)
// is met. When fewer than 4 passwords were supplied via -p and a TTY is
// available, it collects them interactively: keys 1-3 (strong keys), password1,
// then optionally additional passwords (up to the 3+10 web-tool cap). Non-interactive
// runs still require -p to be passed explicitly.
//
// The interactive ordering matches the web tool's keys[] layout:
//
//	keys[0..2] = 3 strong keys (key-derive output, 128-hex each)
//	keys[3]    = password1
//	keys[4..]  = additional passwords (optional)
func resolvePasswords() error {
	// Fully supplied (≥4) via -p: use as-is. Zero supplied + TTY: collect all
	// interactively. Partial (1-3) is ambiguous (which slot do they fill?), so
	// require either all via -p or none (then interactive).
	if len(dataCipherPasswords) >= 4 {
		return nil
	}
	if len(dataCipherPasswords) > 0 || !isStdinTerminal() {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.password_required"))
	}

	// Collect the 4 required entries interactively.
	// keys 1-3 are strong keys; shown as "key N", masked via Password.
	// Each is validated live against the web tool's high-strength rule
	// (IsPasswordHighStrength: >=128 hex chars, >=15 distinct chars).
	for i := 0; i < 3; i++ {
		keyNum := i + 1
		v, err := param.Password(i18n.TWithData("data_cipher.prompt.key_n", map[string]interface{}{
			"N": keyNum,
		}), i18n.T("data_cipher.prompt.key_help"), param.WithValidator(highStrengthKeyValidator(keyNum)))
		if err != nil {
			return err
		}
		dataCipherPasswords = append(dataCipherPasswords, v)
	}
	// password1 (required). Validated live against the web tool's composite rule
	// (IsPassword1Valid: high strength OR letter+digit+special and >=8 chars).
	pw1, err := param.Password(i18n.T("data_cipher.prompt.password1"), "", param.WithValidator(password1Validator))
	if err != nil {
		return err
	}
	dataCipherPasswords = append(dataCipherPasswords, pw1)

	// password2 & password3 are DEFAULT slots (web form renders them by default:
	// keys = ["","","","","",""]; they are optional but always presented). An empty
	// answer is a valid value (an empty-string password participates in key
	// derivation, just like the web tool), so we always ask both and never skip.
	for i := 2; i <= 3; i++ { // i = password number (2, 3)
		extra, err := param.Input(i18n.TWithData("data_cipher.prompt.password_optional", map[string]interface{}{
			"N": i,
		}), "", i18n.T("data_cipher.prompt.password_optional_help"), param.WithoutRequired())
		if err != nil {
			return err
		}
		dataCipherPasswords = append(dataCipherPasswords, extra)
	}

	// password4+ are NOT default slots — they are added via the "add password"
	// button on the web. Here, empty input ends collection; anything else adds
	// another password, up to the 3+10 = 13 cap.
	for len(dataCipherPasswords) < maxKeysCount {
		pwNum := len(dataCipherPasswords) - 2 // index 6 -> password4
		extra, err := param.Input(i18n.TWithData("data_cipher.prompt.password_optional", map[string]interface{}{
			"N": pwNum,
		}), "", i18n.T("data_cipher.prompt.password_optional_help"), param.WithoutRequired())
		if err != nil {
			return err
		}
		if strings.TrimSpace(extra) == "" {
			break
		}
		dataCipherPasswords = append(dataCipherPasswords, extra)
	}
	return nil
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
// (already validated live above) and the -p flag path (which bypasses the live
// validators). Rules, mirroring the web tool exactly:
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

// available and --output was not given. The default shown is the caller-provided
// fallback (encrypt: timestamped zip; decrypt: decrypted-<originalname>). In a
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
	out, err := param.Input(message, fallback, "", param.WithoutRequired())
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		out = fallback
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
