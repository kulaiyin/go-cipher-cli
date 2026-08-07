package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

var (
	argon2Salt         string
	argon2Iterations   int
	argon2MemoryMB     int
	argon2Parallelism  int
	argon2KeyLength    int
	argon2JSON         bool
	argon2SecretsStdin bool
)

// argon2JSONOutput is the machine-readable result emitted by argon2id --json.
type argon2JSONOutput struct {
	Success        bool   `json:"success"`
	Algorithm      string `json:"algorithm"`
	Salt           string `json:"salt"`       // base64
	SaltHex        string `json:"salt_hex"`   // hex
	KeyHex         string `json:"key_hex"`    // hex
	KeyBase64      string `json:"key_base64"` // base64
	Iterations     int    `json:"iterations"`
	MemoryMiB      int    `json:"memory_mib"`
	Parallelism    int    `json:"parallelism"`
	KeyLength      int    `json:"key_length"`
	ProcessingTime int64  `json:"processing_time_ms"`
	Error          string `json:"error,omitempty"`
}

var argon2idCmd = &cobra.Command{
	Use:          "argon2id [flags]",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateArgon2Flags(); err != nil {
			return err
		}
		if err := validateArgon2SecretsExclusive(); err != nil {
			return err
		}

		// password is carried as bytes end-to-end so it can be wiped right
		// after the derivation. There are three mutually exclusive ways it
		// enters the pipeline:
		//   - --secrets-stdin: line 1 is the password, line 2 the salt hex,
		//     both read straight into wipeable bytes.
		//   - stdin is a TTY: prompt on stderr and read with echo disabled via
		//     term.ReadPassword (the password never lands in shell history or
		//     argv); the salt still comes from --salt.
		//   - stdin is piped/redirected without --secrets-stdin: refuse, so a
		//     stray pipe can never silently derive from an empty password.
		// The salt is not sensitive and stays a string.
		var password []byte
		var saltHex string
		switch {
		case argon2SecretsStdin:
			p, s, err := readArgon2Secrets()
			if err != nil {
				return err
			}
			password, saltHex = p, s
		case term.IsTerminal(int(os.Stdin.Fd())):
			p, err := readArgon2PasswordTTY()
			if err != nil {
				return err
			}
			password = p
			saltHex = argon2Salt
		default:
			return fmt.Errorf("%s", i18n.T("argon2id.error.stdin_piped_no_flag"))
		}
		defer clear(password)

		// Resolve the salt: an explicit salt value, else a freshly
		// generated random 16-byte salt.
		if saltHex == "" {
			saltHex = kdf.GenerateSalt(16)
		}
		salt, err := hex.DecodeString(saltHex)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("argon2id.error.invalid_salt"), err)
		}

		cfg := kdf.Argon2Config{
			Salt:        salt,
			Iterations:  argon2Iterations,
			MemorySize:  argon2MemoryMB * 1024, // Argon2Config.MemorySize is in KiB, flag is in MB
			Parallelism: argon2Parallelism,
			HashLength:  argon2KeyLength,
		}

		// Run the derivation, showing a simulated progress bar on stderr when
		// stderr is a terminal. It is shown in both text and --json modes (the
		// JSON result goes to stdout, so the stderr bar never corrupts it) and
		// suppressed when stderr is piped. The bar is flushed to its 100% state
		// before the result is printed so the final line is never lost.
		var result kdf.KDFResult
		if term.IsTerminal(int(os.Stderr.Fd())) {
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				runArgon2Progress(done, cfg)
			}()
			result = kdf.Argon2(password, cfg)
			close(done)
			wg.Wait()
		} else {
			result = kdf.Argon2(password, cfg)
		}

		if !result.Success {
			if argon2JSON {
				emitArgon2JSON(result, salt)
			}
			return fmt.Errorf("%s: %s", i18n.T("argon2id.error.derive_failed"), result.Error)
		}

		if argon2JSON {
			// Refuse to emit the derived key to a terminal; --json is the
			// machine interface and must be piped/redirected.
			if term.IsTerminal(int(os.Stdout.Fd())) {
				return fmt.Errorf("%s", i18n.T("argon2id.error.json_tty_denied"))
			}
			emitArgon2JSON(result, salt)
			return nil
		}
		emitArgon2Text(result, salt)
		return nil
	},
}

// validateArgon2Flags rejects non-positive numeric parameters up front instead
// of silently falling back to kdf defaults.
func validateArgon2Flags() error {
	if argon2Iterations <= 0 {
		return fmt.Errorf("%s", i18n.T("argon2id.error.invalid_iterations"))
	}
	if argon2MemoryMB <= 0 {
		return fmt.Errorf("%s", i18n.T("argon2id.error.invalid_memory"))
	}
	if argon2Parallelism <= 0 {
		return fmt.Errorf("%s", i18n.T("argon2id.error.invalid_parallelism"))
	}
	if argon2KeyLength <= 0 {
		return fmt.Errorf("%s", i18n.T("argon2id.error.invalid_key_length"))
	}
	return nil
}

// validateArgon2SecretsExclusive rejects --secrets-stdin mixed with --salt so
// the salt source stays unambiguous (stdin line 2 vs. the flag).
func validateArgon2SecretsExclusive() error {
	if !argon2SecretsStdin {
		return nil
	}
	if argon2Salt != "" {
		return fmt.Errorf("%s", i18n.T("argon2id.error.secrets_stdin_conflict_salt"))
	}
	return nil
}

// readArgon2Secrets reads line 1 (password) and line 2 (salt hex) from stdin.
// The password is returned as bytes so callers can wipe it after the
// derivation. A missing final line is tolerated (EOF): the salt stays empty
// and falls back to random generation below.
func readArgon2Secrets() (password []byte, saltHex string, err error) {
	r := bufio.NewReader(os.Stdin)
	raw, err := r.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, "", err
	}
	password = bytes.TrimSpace(raw)
	saltLine, err := r.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, "", err
	}
	return password, string(bytes.TrimSpace(saltLine)), nil
}

// runArgon2Progress renders a simulated progress bar on stderr until done is
// closed, then prints a final 100% state and a newline so subsequent output
// starts on a fresh line. The bar estimates the total cost from the Argon2
// config (iterations × memory ÷ parallelism) and fills asymptotically toward a
// soft cap, so it can never reach 100% before the derivation really finishes.
// It runs in a goroutine while the synchronous derivation executes.
func runArgon2Progress(done <-chan struct{}, cfg kdf.Argon2Config) {
	label := i18n.T("argon2id.progress.deriving")
	const (
		width   = 40
		softCap = 0.95
	)
	tau := estimateArgon2Cost(cfg)
	start := time.Now()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			elapsed := time.Since(start).Round(time.Millisecond)
			fmt.Fprintf(os.Stderr, "\r%s [%s>] 100%% %s\n", label,
				strings.Repeat("=", width-1), elapsed)
			return
		case <-ticker.C:
			elapsed := time.Since(start).Round(10 * time.Millisecond)
			progress := softCap * (1 - math.Exp(-elapsed.Seconds()/tau))
			filled := int(progress * width)
			fmt.Fprintf(os.Stderr, "\r%s [%s>%s] %3.0f%% %s", label,
				strings.Repeat("=", filled),
				strings.Repeat(" ", width-filled-1),
				progress*100, elapsed)
		}
	}
}

// estimateArgon2Cost returns a rough expected duration in seconds for an
// Argon2id configuration. Cost scales with iterations × memory (in KiB) and
// shrinks with parallelism, normalized against the CLI defaults (3 iterations,
// 64 MB, 1 parallelism) and a measured baseline.
func estimateArgon2Cost(cfg kdf.Argon2Config) float64 {
	const (
		baseIterations   = 3
		baseMemoryKiB    = 64 * 1024
		baseParallelism  = 1
		baseDurationSecs = 0.12
	)
	cost := float64(cfg.Iterations) / baseIterations *
		float64(cfg.MemorySize) / baseMemoryKiB *
		float64(baseParallelism) / float64(cfg.Parallelism)
	return baseDurationSecs * cost
}

// emitArgon2Text prints the human-readable output (default mode). The derived
// key is masked so it never appears in plaintext on a terminal; the full value
// is available via --json on a redirected stdout.
func emitArgon2Text(r kdf.KDFResult, salt []byte) {
	fmt.Println(i18n.TWithData("argon2id.output.algorithm", map[string]interface{}{
		"Memory":      argon2MemoryMB,
		"Iterations":  r.Iterations,
		"Parallelism": argon2Parallelism,
	}))
	fmt.Println(i18n.TWithData("argon2id.output.salt_base64", map[string]interface{}{
		"Salt": base64.StdEncoding.EncodeToString(salt),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.salt_hex", map[string]interface{}{
		"Salt": hex.EncodeToString(salt),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.key_hex", map[string]interface{}{
		"Key": displayMaskKey(r.Data),
	}))
	keyBytes, _ := hex.DecodeString(r.Data)
	defer clear(keyBytes)
	fmt.Println(i18n.TWithData("argon2id.output.key_base64", map[string]interface{}{
		"Key": displayMaskKey(base64.StdEncoding.EncodeToString(keyBytes)),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.key_length", map[string]interface{}{
		"Bits": len(keyBytes) * 8,
	}))
	fmt.Println(i18n.TWithData("argon2id.output.processing_time", map[string]interface{}{
		"Ms": r.ProcessingTime,
	}))
	fmt.Println(i18n.T("argon2id.output.mask_hint"))
}

// emitArgon2JSON prints the machine-readable output (--json mode).
func emitArgon2JSON(r kdf.KDFResult, salt []byte) {
	keyBytes, _ := hex.DecodeString(r.Data)
	defer clear(keyBytes)
	out := argon2JSONOutput{
		Success:        r.Success,
		Algorithm:      "argon2id",
		Salt:           base64.StdEncoding.EncodeToString(salt),
		SaltHex:        hex.EncodeToString(salt),
		KeyHex:         r.Data,
		KeyBase64:      base64.StdEncoding.EncodeToString(keyBytes),
		Iterations:     r.Iterations,
		MemoryMiB:      argon2MemoryMB,
		Parallelism:    argon2Parallelism,
		KeyLength:      r.HashLength,
		ProcessingTime: r.ProcessingTime,
	}
	if !r.Success {
		out.Error = r.Error
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.T("argon2id.error.json_marshal"))
		return
	}
	fmt.Println(string(data))
	clear(data)
}

// readArgon2PasswordTTY prompts on stderr and reads a password from the
// terminal with echo disabled via term.ReadPassword. It must only be called
// when stdin is an interactive TTY. The returned bytes are wiped by the caller
// after the derivation.
func readArgon2PasswordTTY() ([]byte, error) {
	fmt.Fprint(os.Stderr, i18n.T("argon2id.prompt.password"))
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("argon2id.error.tty_read_failed"), err)
	}
	// Newline so the prompt line is closed before later output/progress.
	fmt.Fprintln(os.Stderr)
	return bytes.TrimSpace(pw), nil
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		argon2idCmd.Short = i18n.T("argon2id.short")
		argon2idCmd.Long = i18n.T("argon2id.long")
	})

	// The password arrives via --secrets-stdin or an interactive TTY prompt;
	// there is no plaintext password flag.
	argon2idCmd.Flags().StringVar(&argon2Salt, "salt", "", i18n.T("argon2id.flag.salt"))
	argon2idCmd.Flags().BoolVar(&argon2SecretsStdin, "secrets-stdin", false, i18n.T("argon2id.flag.secrets_stdin"))
	argon2idCmd.Flags().IntVar(&argon2Iterations, "iterations", 3, i18n.T("argon2id.flag.iterations"))
	argon2idCmd.Flags().IntVar(&argon2MemoryMB, "memory", 64, i18n.T("argon2id.flag.memory"))
	argon2idCmd.Flags().IntVar(&argon2Parallelism, "parallelism", 1, i18n.T("argon2id.flag.parallelism"))
	argon2idCmd.Flags().IntVar(&argon2KeyLength, "key-length", 64, i18n.T("argon2id.flag.key_length"))
	argon2idCmd.Flags().BoolVar(&argon2JSON, "json", false, i18n.T("argon2id.flag.json"))
	rootCmd.AddCommand(argon2idCmd)
}
