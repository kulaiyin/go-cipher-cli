package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	argon2Password         string
	argon2Salt             string
	argon2Iterations       int
	argon2MemoryMB         int
	argon2Parallelism      int
	argon2KeyLength        int
	argon2JSON             bool
	argon2EchoPassword     bool
	argon2PromptedPassword string
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
	Password       string `json:"password,omitempty"`
	Error          string `json:"error,omitempty"`
}

var argon2idCmd = &cobra.Command{
	Use:          "argon2id -p <password> [flags]",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateArgon2Flags(); err != nil {
			return err
		}

		password, err := resolveArgon2Password()
		if err != nil {
			return err
		}

		// Resolve the salt: an explicit --salt hex value, else a freshly
		// generated random 16-byte salt.
		saltHex := argon2Salt
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
				emitArgon2JSON(result, salt, echoArgon2Password())
			}
			return fmt.Errorf("%s: %s", i18n.T("argon2id.error.derive_failed"), result.Error)
		}

		if argon2JSON {
			emitArgon2JSON(result, salt, echoArgon2Password())
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

// emitArgon2Text prints the human-readable output (default mode).
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
		"Key": r.Data,
	}))
	keyBytes, _ := hex.DecodeString(r.Data)
	fmt.Println(i18n.TWithData("argon2id.output.key_base64", map[string]interface{}{
		"Key": base64.StdEncoding.EncodeToString(keyBytes),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.key_length", map[string]interface{}{
		"Bits": len(keyBytes) * 8,
	}))
	fmt.Println(i18n.TWithData("argon2id.output.processing_time", map[string]interface{}{
		"Ms": r.ProcessingTime,
	}))
}

// emitArgon2JSON prints the machine-readable output (--json mode).
// echoPassword, when non-empty, is written to the password field (interactive prompt only).
func emitArgon2JSON(r kdf.KDFResult, salt []byte, echoPassword string) {
	keyBytes, _ := hex.DecodeString(r.Data)
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
		Password:       echoPassword,
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
}

// echoArgon2Password returns the password to echo in --json output.
// Only echoes when --echo-password is set and the password was prompted
// interactively; a -p value is never echoed.
func echoArgon2Password() string {
	if !argon2EchoPassword || argon2Password != "" {
		return ""
	}
	return argon2PromptedPassword
}

// resolveArgon2Password returns the derivation password. The password must be
// supplied via -p; there is no interactive prompt.
func resolveArgon2Password() (string, error) {
	if argon2Password == "" {
		return "", fmt.Errorf("%s", i18n.T("argon2id.error.password_required"))
	}
	return argon2Password, nil
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		argon2idCmd.Short = i18n.T("argon2id.short")
		argon2idCmd.Long = i18n.T("argon2id.long")
	})

	// -p is optional: it is prompted interactively (hidden input) when omitted.
	argon2idCmd.Flags().StringVarP(&argon2Password, "password", "p", "", i18n.T("argon2id.flag.password"))
	argon2idCmd.Flags().StringVar(&argon2Salt, "salt", "", i18n.T("argon2id.flag.salt"))
	argon2idCmd.Flags().IntVar(&argon2Iterations, "iterations", 3, i18n.T("argon2id.flag.iterations"))
	argon2idCmd.Flags().IntVar(&argon2MemoryMB, "memory", 64, i18n.T("argon2id.flag.memory"))
	argon2idCmd.Flags().IntVar(&argon2Parallelism, "parallelism", 1, i18n.T("argon2id.flag.parallelism"))
	argon2idCmd.Flags().IntVar(&argon2KeyLength, "key-length", 64, i18n.T("argon2id.flag.key_length"))
	argon2idCmd.Flags().BoolVar(&argon2JSON, "json", false, i18n.T("argon2id.flag.json"))
	argon2idCmd.Flags().BoolVar(&argon2EchoPassword, "echo-password", false, "echo prompted password as plaintext in --json output (interactive only)")
	rootCmd.AddCommand(argon2idCmd)
}
