package cmd

// data-cipher-pipe is the argon2id/key-derive-pipe style input layer for
// data-cipher: the secrets (3 strong keys, password1, extra password) never
// enter argv or shell history. The 3 strong keys can only be passed via a JSON
// object on stdin; when stdin is a TTY (no pipe) the command refuses to run.
// password1 and the optional extra password may be prompted interactively when
// the piped JSON omits them. Every secret is carried as wipeable []byte and
// zeroed after use.
//
// The encryption/decryption pipeline reuses the exact same primitives as
// data-cipher (aesgcm, container, safety.AssemblePackageKey), so the produced
// bundles are byte-for-byte compatible with the web tool (golden vectors guard).

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/safety"
	"go-cipher-cli/internal/util"
)

// dataCipherPipeParams is the resolved parameter set for data-cipher-pipe.
// Keys/Password1/Extra are wipeable bytes; the rest is public metadata.
type dataCipherPipeParams struct {
	Mode      string
	InputType string
	Text      string
	File      string
	Salt      string
	Hint      string
	Output    string
	HintIDs   []string // question-answer question IDs chosen for password1
	Keys      [][]byte
	Password1 []byte
	Extras    [][]byte // optional additional passwords (web keys[4..])
}

// wipeDataCipherPipeSecrets zeroes every secret byte carried by the params.
func wipeDataCipherPipeSecrets(p *dataCipherPipeParams) {
	for _, k := range p.Keys {
		util.WipeBytes(k)
	}
	util.WipeBytes(p.Password1)
	for _, e := range p.Extras {
		util.WipeBytes(e)
	}
}

// dataCipherPipeCmd takes NO flags: every parameter arrives as a JSON object on
// stdin (or an interactive TTY prompt), and the secrets are wipeable bytes.
var dataCipherPipeCmd = &cobra.Command{
	Use:          "data-cipher-pipe",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return runDataCipherPipeInteractive()
		}
		return runDataCipherPipe()
	},
}

// runDataCipherPipe is the piped-JSON branch: it reads the JSON object, resolves
// the salt/hint, falls back to the interactive TTY flow for any missing secret
// (reusing the piped fields), then encrypts or decrypts.
func runDataCipherPipe() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	defer util.WipeBytes(data)

	params, err := parseDataCipherPipeJSON(data)
	if err != nil {
		return err
	}
	defer wipeDataCipherPipeSecrets(&params)

	if err := validateDataCipherPipeNonSecretFields(&params); err != nil {
		return err
	}

	if params.Mode == "encrypt" {
		return runDataCipherPipeEncrypt(&params)
	}
	return runDataCipherPipeDecrypt(&params)
}

// parseDataCipherPipeJSON parses the stdin JSON object into params. Every secret
// field is copied into caller-owned slices so the caller's wipe zeroes them.
func parseDataCipherPipeJSON(data []byte) (dataCipherPipeParams, error) {
	p := dataCipherPipeParams{}
	if v, err := jsonparser.GetString(data, "mode"); err == nil {
		p.Mode = strings.ToLower(strings.TrimSpace(v))
	}
	if v, err := jsonparser.GetString(data, "inputType"); err == nil {
		p.InputType = strings.ToLower(strings.TrimSpace(v))
	}
	if v, err := jsonparser.GetString(data, "text"); err == nil {
		p.Text = v
	}
	if v, err := jsonparser.GetString(data, "file"); err == nil {
		p.File = v
	}
	if v, err := jsonparser.GetString(data, "salt"); err == nil {
		p.Salt = v
	}
	if v, err := jsonparser.GetString(data, "hint"); err == nil {
		p.Hint = v
	}
	if v, err := jsonparser.GetString(data, "output"); err == nil {
		p.Output = v
	}
	if arr, _, _, err := jsonparser.Get(data, "keys"); err == nil {
		_, _ = jsonparser.ArrayEach(arr, func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
			key := make([]byte, len(value))
			copy(key, value)
			p.Keys = append(p.Keys, key)
		})
	}
	if pw, _, _, err := jsonparser.Get(data, "password1"); err == nil && len(pw) > 0 {
		p.Password1 = make([]byte, len(pw))
		copy(p.Password1, pw)
	}
	if exArr, _, _, err := jsonparser.Get(data, "extraPasswords"); err == nil {
		_, _ = jsonparser.ArrayEach(exArr, func(value []byte, _ jsonparser.ValueType, _ int, _ error) {
			ex := make([]byte, len(value))
			copy(ex, value)
			p.Extras = append(p.Extras, ex)
		})
	}
	return p, nil
}

// validateDataCipherPipeNonSecretFields checks mode/input-type/content before any
// interactive collection, so a doomed run fails fast.
func validateDataCipherPipeNonSecretFields(p *dataCipherPipeParams) error {
	if p.Mode != "encrypt" && p.Mode != "decrypt" {
		return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.invalid_mode", map[string]interface{}{
			"Mode": p.Mode,
		}))
	}
	if p.Mode == "encrypt" {
		if p.InputType != "" && p.InputType != "text" && p.InputType != "file" {
			return fmt.Errorf("%s", i18n.TWithData("data_cipher.error.invalid_input_type", map[string]interface{}{
				"Type": p.InputType,
			}))
		}
		if p.InputType == "text" && strings.TrimSpace(p.Text) == "" {
			return fmt.Errorf("%s", i18n.T("data_cipher.error.empty_input"))
		}
		if p.InputType == "file" && p.File == "" {
			return fmt.Errorf("%s", i18n.T("data_cipher.error.input_required"))
		}
	} else if p.File == "" {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.input_required"))
	}
	return nil
}

// runDataCipherPipeEncrypt encrypts the piped content with the resolved
// secrets and writes the zip bundle to the output path.
func runDataCipherPipeEncrypt(p *dataCipherPipeParams) error {
	salt := p.Salt
	if salt == "" {
		salt = safety.BytesToHex(safety.GenerateRandomBytes(64))
	}
	if _, err := hex.DecodeString(salt); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.salt_hex"), err)
	}

	in, err := resolveDataCipherPipeInput(p)
	if err != nil {
		return err
	}

	if err := resolveDataCipherPipePasswords(p, salt, true, nil); err != nil {
		return err
	}
	if err := validateDataCipherPipeSecrets(p); err != nil {
		return err
	}

	passwords := buildDataCipherPipePasswordList(p)
	defer wipePasswordList(passwords)

	ct, err := aesgcm.EncryptWithPassword(in.data, salt, passwords)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}
	bin, err := container.AssembleDownloadData(dataCipherContainerVersion, 0, salt, ct)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}
	assembleKey, err := safety.AssemblePackageKey(passwords, salt)
	if err != nil {
		return err
	}
	hints := p.HintIDs
	if hints == nil {
		hints = []string{}
	}
	meta := &container.MetaData{
		Version:       dataCipherContainerVersion,
		Salt:          salt,
		FileName:      in.fileName,
		FileType:      in.mimeType,
		Hint:          p.Hint,
		SelectedHints: hints,
		SHA256:        safety.SHA256Hex(string(bin)),
		CreatedAt:     time.Now().UnixMilli(),
	}
	meta.SignMetaData(assembleKey)
	metaJSON, err := container.MarshalMetaData(meta)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}
	zipData, err := container.CompressBundle(container.BundleEntries{Bin: bin, Meta: metaJSON})
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.encrypt_failed"), err)
	}

	out, err := resolveDataCipherPipeOutput(i18n.T("data_cipher.prompt.output_encrypt"), p.Output, fmt.Sprintf("encrypted-%d.zip", time.Now().UnixMilli()))
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, zipData, 0o644); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.write_output"), err)
	}
	fmt.Println(i18n.TWithData("data_cipher.output.encrypt_success", map[string]interface{}{
		"Size": len(in.data),
		"Path": out,
	}))
	if isVolatilePath(out) {
		fmt.Println(i18n.T("data_cipher.output.volatile_reminder"))
	}
	return nil
}

// runDataCipherPipeDecrypt parses the zip, resolves the secrets (re-answering
// stored question-answer questions when present), and writes the plaintext.
func runDataCipherPipeDecrypt(p *dataCipherPipeParams) error {
	zipData, err := readInputFile(p.File)
	if err != nil {
		return err
	}
	entries, err := container.DecompressBundle(zipData)
	if err != nil {
		return err
	}
	meta, err := container.ParseMetaData(entries.Meta)
	if err != nil {
		return err
	}
	if err := meta.ValidateMetaDataFields(); err != nil {
		return err
	}
	if actual := safety.SHA256Hex(string(entries.Bin)); actual != meta.SHA256 {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.sha256_mismatch"))
	}
	if !meta.VerifyMetaHash() {
		return fmt.Errorf("%s", i18n.T("data_cipher.error.meta_tampered"))
	}
	parsed, err := container.ExtractDecryptedData(entries.Bin)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.parse_container"), err)
	}
	decryptSalt := parsed.SaltSeed
	if meta.Hint != "" {
		fmt.Println(i18n.TWithData("data_cipher.output.decrypt_hint", map[string]interface{}{
			"Hint": meta.Hint,
		}))
	}

	if err := resolveDataCipherPipePasswords(p, parsed.SaltSeed, false, meta.SelectedHints); err != nil {
		return err
	}
	if err := validateDataCipherPipeSecrets(p); err != nil {
		return err
	}
	passwords := buildDataCipherPipePasswordList(p)
	defer wipePasswordList(passwords)

	assembleKey, err := safety.AssemblePackageKey(passwords, parsed.SaltSeed)
	if err != nil {
		return err
	}
	storedIntegrity := meta.IntegrityHash
	if !meta.VerifyIntegrityHash(assembleKey) {
		decryptSalt = safety.HMACSHA3512([]byte(decryptSalt), []byte(storedIntegrity))
	}
	pt, err := aesgcm.DecryptWithPassword(parsed.EncryptedData, decryptSalt, passwords)
	if err != nil {
		return fmt.Errorf("%s: %s", i18n.T("data_cipher.error.decrypt_failed"), strings.TrimRight(err.Error(), "!"))
	}

	base := "decrypted.txt"
	if meta.FileName != "" {
		base = "decrypted-" + meta.FileName
	}
	out, err := resolveDataCipherPipeOutput(i18n.T("data_cipher.prompt.output_decrypt"), p.Output, base)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, pt, 0o644); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("data_cipher.error.write_output"), err)
	}
	fmt.Println(i18n.TWithData("data_cipher.output.decrypt_success", map[string]interface{}{
		"Size": len(pt),
		"Path": out,
	}))
	return nil
}

// resolveDataCipherPipeInput builds the cipher input from the piped fields.
func resolveDataCipherPipeInput(p *dataCipherPipeParams) (*cipherInput, error) {
	if p.InputType == "text" || (p.Mode == "encrypt" && p.InputType == "" && p.Text != "") {
		return &cipherInput{inputType: "text", data: []byte(p.Text), mimeType: "text/plain"}, nil
	}
	path := p.File
	if path == "" {
		path = p.Text
	}
	if path == "" {
		return nil, fmt.Errorf("%s", i18n.T("data_cipher.error.input_required"))
	}
	data, err := readInputFile(path)
	if err != nil {
		return nil, err
	}
	return &cipherInput{inputType: "file", data: data, fileName: filepath.Base(path), mimeType: detectMimeType(path)}, nil
}

// buildDataCipherPipePasswordList assembles the key/password list in the web
// tool's keys[] layout: [key1,key2,key3,password1,extra...].
func buildDataCipherPipePasswordList(p *dataCipherPipeParams) [][]byte {
	list := make([][]byte, 0, len(p.Keys)+len(p.Extras)+1)
	list = append(list, p.Keys...)
	list = append(list, p.Password1)
	list = append(list, p.Extras...)
	return list
}

// wipePasswordList zeroes every entry of a resolved password list.
func wipePasswordList(list [][]byte) {
	for _, b := range list {
		util.WipeBytes(b)
	}
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		dataCipherPipeCmd.Short = i18n.T("data_cipher_pipe.short")
		dataCipherPipeCmd.Long = i18n.T("data_cipher_pipe.long")
	})
	rootCmd.AddCommand(dataCipherPipeCmd)
}
