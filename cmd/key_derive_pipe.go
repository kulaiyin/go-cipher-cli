package cmd

// argon2id-style key-derive input layer: the password never enters argv. It
// arrives via a JSON object piped on stdin (auto-detected) or, when stdin is a
// TTY, a terminal prompt with echo disabled. The password and derived keys are
// carried as wipeable []byte and zeroed after use.
//
// key-derive-pipe is isolated from key_derive.go: the legacy keyDeriveCmd and
// its declarative param.Field lifecycle are untouched.

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/buger/jsonparser"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/util"
	"go-cipher-cli/internal/validation"
)

// keyDerivePipeInput mirrors the stdin JSON object. Every field is optional in
// the JSON; the password is intentionally absent — it is pulled straight into
// wipeable []byte by resolveKeyDerivePipePassword, never materialised as a
// Go string.
type keyDerivePipeInput struct {
	Mode     string
	Input    string
	Salt     string
	Hint     string
	Strength string
	Config   string // restore only: path to a recovery config file
}

// keyDerivePipeParams is the resolved parameter set. Password is wipeable and
// wiped by runKeyDerivePipe after the derivation.
type keyDerivePipeParams struct {
	Mode     string
	Input    string
	Salt     string
	Hint     string
	Strength kdf.Strength
	Config   string
	Password []byte
}

// runKeyDerivePipe collects inputs (piped JSON, or empty on a TTY), runs
// DeriveKeySetBytes, and returns the result. The password and stdin bytes are
// wiped on return. The result's RawKeys/RawUUID are NOT wiped here — they are
// the secret product returned to the caller, which MUST wipe them after use.
func runKeyDerivePipe() (kdf.KeySetBytesResult, error) {
	var result kdf.KeySetBytesResult

	params, stdinData, err := resolveKeyDerivePipeParams()
	if err != nil {
		return result, err
	}
	// stdinData may carry the password in cleartext.
	defer util.WipeBytes(params.Password)
	defer util.WipeBytes(stdinData)

	if err := validateKeyDerivePipeParams(params); err != nil {
		return result, err
	}

	salt := params.Salt
	if salt == "" {
		if params.Mode == "restore" {
			cfg, err := loadRecoveryConfig(params.Config)
			if err != nil {
				return result, fmt.Errorf("failed to read recovery config: %w", err)
			}
			if cfg.Salt == "" {
				return result, fmt.Errorf("recovery config is missing a salt")
			}
			salt = cfg.Salt
			if params.Strength == "" {
				params.Strength = kdf.Strength(cfg.Strength)
			}
		} else {
			salt = kdf.GenerateSalt(64)
		}
	}

	input := cleanKeyDeriveText(params.Input)
	result = kdf.DeriveKeySetBytes(input, params.Password, salt, params.Strength)
	if !result.Success {
		return result, fmt.Errorf("key derivation failed: %s", result.Error)
	}
	return result, nil
}

// resolveKeyDerivePipeParams reads the stdin JSON (empty on a TTY) and resolves
// it into keyDerivePipeParams. Non-password fields are validated before the
// password is collected, so a doomed run (e.g. invalid mode) fails fast instead
// of prompting on /dev/tty.
func resolveKeyDerivePipeParams() (keyDerivePipeParams, []byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return keyDerivePipeParams{}, nil, nil
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return keyDerivePipeParams{}, nil, err
	}

	in := keyDerivePipeInput{}
	if v, err := jsonparser.GetString(data, "mode"); err == nil {
		in.Mode = v
	}
	if v, err := jsonparser.GetString(data, "input"); err == nil {
		in.Input = v
	}
	if v, err := jsonparser.GetString(data, "salt"); err == nil {
		in.Salt = v
	}
	if v, err := jsonparser.GetString(data, "hint"); err == nil {
		in.Hint = v
	}
	if v, err := jsonparser.GetString(data, "strength"); err == nil {
		in.Strength = v
	}
	if v, err := jsonparser.GetString(data, "config"); err == nil {
		in.Config = v
	}

	p := keyDerivePipeParams{
		Mode:     strings.ToLower(strings.TrimSpace(in.Mode)),
		Input:    in.Input,
		Salt:     in.Salt,
		Hint:     in.Hint,
		Strength: kdf.Strength(strings.ToLower(strings.TrimSpace(in.Strength))),
		Config:   in.Config,
	}
	// Fail on bad non-secret inputs before touching the password path, which
	// may block on /dev/tty.
	if err := validateKeyDerivePipeNonPasswordFields(p); err != nil {
		return keyDerivePipeParams{}, data, err
	}

	pw, err := resolveKeyDerivePipePassword(data)
	if err != nil {
		return keyDerivePipeParams{}, data, err
	}
	p.Password = pw
	return p, data, nil
}

// resolveKeyDerivePipePassword returns the password as wipeable bytes: verbatim
// from the JSON "password" field, or — when absent — read from /dev/tty with
// echo disabled (the stdin pipe is already consumed by the JSON).
func resolveKeyDerivePipePassword(data []byte) ([]byte, error) {
	if pw, _, _, err := jsonparser.Get(data, "password"); err == nil && len(pw) > 0 {
		// Copy into a buffer we own so the caller's WipeBytes zeroes our slice,
		// not jsonparser's internal buffer.
		out := make([]byte, len(pw))
		copy(out, pw)
		return out, nil
	}
	p, err := util.ReadPasswordTTYFromDevice("Enter password: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password from terminal: %w", err)
	}
	return p, nil
}

// validateKeyDerivePipeNonPasswordFields checks mode/input/salt/config/strength.
// Called before the password is collected so a doomed run fails without a
// /dev/tty prompt.
func validateKeyDerivePipeNonPasswordFields(p keyDerivePipeParams) error {
	mode := p.Mode
	if mode == "" {
		mode = "generate"
	}
	if mode != "generate" && mode != "restore" {
		return fmt.Errorf("invalid mode: must be generate or restore")
	}

	// Input is public probe text, not a secret; the string validator is safe.
	if err := validation.ValidateKeyDeriveInput(p.Input); err != nil {
		return err
	}

	if p.Salt != "" {
		if _, err := hex.DecodeString(p.Salt); err != nil {
			return fmt.Errorf("invalid salt: must be a hex string: %w", err)
		}
	}

	if mode == "restore" && p.Config == "" {
		return fmt.Errorf("restore mode requires a recovery config (--config)")
	}
	if mode == "generate" && p.Config != "" {
		return fmt.Errorf("generate mode does not accept --config")
	}

	// Empty strength defaults to medium downstream; only reject an explicit
	// invalid value.
	switch p.Strength {
	case "", kdf.StrengthBasic, kdf.StrengthMedium, kdf.StrengthAdvanced:
	default:
		return fmt.Errorf("invalid strength: must be basic, medium, or advanced")
	}
	return nil
}

// validateKeyDerivePipeParams runs the non-password checks plus the password
// check. The password is validated as bytes (never a string copy).
func validateKeyDerivePipeParams(p keyDerivePipeParams) error {
	if err := validateKeyDerivePipeNonPasswordFields(p); err != nil {
		return err
	}
	if err := validatePasswordBytes(p.Password); err != nil {
		return err
	}
	return nil
}

// validatePasswordBytes mirrors validation.ValidateKeyDerivePassword +
// safety.IsPassword1Valid on bytes, so no immutable Go string copy of the
// password is created. The trimmed copy it allocates is wiped before return.
//
// Rules (identical to the string-based path): high strength (>= 128 bytes, >=
// 15 distinct hex chars) OR (>= 8 runes AND letter + digit + special, where
// special is any non-ASCII-alphanumeric per the web tool's /[^A-Za-z0-9]/).
func validatePasswordBytes(pw []byte) error {
	// Trim ASCII whitespace into a wipeable copy.
	trimmed := make([]byte, 0, len(pw))
	start, end := 0, len(pw)
	for start < end && isASCIISpace(pw[start]) {
		start++
	}
	for end > start && isASCIISpace(pw[end-1]) {
		end--
	}
	trimmed = append(trimmed, pw[start:end]...)
	defer util.WipeBytes(trimmed)

	if isHighStrengthBytes(trimmed) {
		return nil
	}
	if utf8.RuneCount(trimmed) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hasLetter, hasDigit, hasSpecial := false, false, false
	for _, b := range trimmed {
		switch {
		case (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'):
			hasLetter = true
		case b >= '0' && b <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if !(hasLetter && hasDigit && hasSpecial) {
		return fmt.Errorf("password must contain a letter, a digit, and a special character")
	}
	return nil
}

// isHighStrengthBytes mirrors safety.IsPasswordHighStrength: length >= 128 and
// the lowercase hex character set reaches >= 15 distinct digits/letters.
func isHighStrengthBytes(pw []byte) bool {
	if len(pw) < 128 {
		return false
	}
	seen := make(map[byte]struct{}, 16)
	for _, b := range pw {
		if b >= 'A' && b <= 'F' { // fold A-F to lowercase for hex dedup
			b += 'a' - 'A'
		}
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') {
			seen[b] = struct{}{}
		}
		if len(seen) >= 15 {
			return true
		}
	}
	return false
}

// isASCIISpace reports whether b is whitespace trimmed by strings.TrimSpace.
func isASCIISpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// keyDerivePipeCmd takes NO flags: every parameter arrives as a JSON object on
// stdin, and the password is carried as wipeable bytes end-to-end. The derived
// key set is emitted as JSON on stdout. When stdin is a TTY (nothing piped) it
// errors instead of hanging.
//
// Usage:
//
//	echo '{"mode":"generate","input":"...","password":"...","salt":"<128hex>","strength":"basic"}' \
//	  | go-cipher-cli key-derive-pipe
var keyDerivePipeCmd = &cobra.Command{
	Use:          "key-derive-pipe",
	Short:        "Derive a key set from a JSON object on stdin (argon2id-style pipe input)",
	Long:         "Derive a key set from a JSON object piped on stdin. The JSON carries mode/input/password/salt/hint/strength/config; the password is read as wipeable bytes and wiped after derivation. Output is a JSON object with the derived keys (hex) on stdout.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("key-derive-pipe requires input on stdin: pipe a JSON object, e.g. echo '{\"mode\":\"generate\",...}' | go-cipher-cli key-derive-pipe")
		}
		result, err := runKeyDerivePipe()
		if err != nil {
			return err
		}
		defer wipeKeySetBytesResult(result)
		emitKeyDerivePipeJSON(result)
		return nil
	},
}

// emitKeyDerivePipeJSON prints the key set as JSON on stdout. The output is
// built byte-by-byte into a wipeable buffer and wiped after writing, so no
// string copy of the keys lingers. Mirrors argon2id.go's emitArgon2JSON.
func emitKeyDerivePipeJSON(r kdf.KeySetBytesResult) {
	buf := make([]byte, 0, 256+3*128+32) // fixed text + 3 keys + uuid (hex)
	buf = append(buf, `{"success":`...)
	buf = strconv.AppendBool(buf, r.Success)
	if r.Success {
		buf = append(buf, `,"algorithm":"argon2id+hkdf","strength":"`...)
		buf = append(buf, string(r.Strength)...)
		buf = append(buf, `","salt":"`...)
		buf = append(buf, r.SaltSeed...) // SaltSeed is already a hex string
		buf = append(buf, `","uuid":"`...)
		buf = appendHex(buf, r.RawUUID)
		buf = append(buf, `","keys":["`...)
		for i, k := range r.RawKeys {
			if i > 0 {
				buf = append(buf, `","`...)
			}
			buf = appendHex(buf, k)
		}
		buf = append(buf, `"],"processing_time_ms":`...)
		buf = strconv.AppendInt(buf, r.ProcessingTime, 10)
		buf = append(buf, '}')
	} else {
		buf = append(buf, `,"error":"`...)
		buf = append(buf, r.Error...)
		buf = append(buf, `"}`...)
	}
	buf = append(buf, '\n')
	defer util.WipeBytes(buf)
	os.Stdout.Write(buf)
}

// wipeKeySetBytesResult zeroes the raw keys/UUID after the command has emitted
// its output.
func wipeKeySetBytesResult(r kdf.KeySetBytesResult) {
	for _, k := range r.RawKeys {
		util.WipeBytes(k)
	}
	util.WipeBytes(r.RawUUID)
}

func init() {
	rootCmd.AddCommand(keyDerivePipeCmd)
}
