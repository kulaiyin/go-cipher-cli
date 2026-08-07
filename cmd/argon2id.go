package cmd

import (
	"encoding/base64"
	"encoding/hex"
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
	"go-cipher-cli/internal/util"
)

var (
	argon2Salt        string
	argon2Iterations  int
	argon2MemoryMB    int
	argon2Parallelism int
	argon2KeyLength   int
	argon2Pipe        bool
	argon2PipeOut     bool
)

var argon2idCmd = &cobra.Command{
	Use:          "argon2id [flags]",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateArgon2Flags(); err != nil {
			return err
		}

		// The password enters via one of two mutually exclusive paths:
		//   - --pipe: line 1 (password) and line 2 (salt hex) arrive on stdin.
		//   - otherwise: only an interactive terminal is accepted, with echo
		//     disabled so the password never lands in shell history or argv.
		var password []byte
		var saltHex string
		if argon2Pipe {
			lines, err := util.ReadLinesStdin(2)
			if err != nil {
				return err
			}
			defer util.WipeLines(lines)
			if len(lines) > 0 {
				password = lines[0]
			}
			if len(lines) > 1 {
				saltHex = string(lines[1])
			}
		} else {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("%s", i18n.T("argon2id.error.stdin_piped"))
			}
			p, err := util.ReadPasswordTTY(i18n.T("argon2id.prompt.password"))
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("argon2id.error.tty_read_failed"), err)
			}
			defer util.WipeBytes(p)
			password = p
			saltHex = argon2Salt
		}

		// Resolve the salt: an explicit salt value, else a freshly
		// generated random 16-byte salt.
		if saltHex == "" {
			saltHex = kdf.GenerateSalt(16)
		}
		saltBytes, err := hex.DecodeString(saltHex)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("argon2id.error.invalid_salt"), err)
		}

		cfg := kdf.Argon2Config{
			Salt:        saltBytes,
			Iterations:  argon2Iterations,
			MemorySize:  argon2MemoryMB * 1024, // Argon2Config.MemorySize is in KiB, flag is in MB
			Parallelism: argon2Parallelism,
			HashLength:  argon2KeyLength,
		}

		// Run the derivation, showing a simulated progress bar on stderr when
		// stderr is a terminal. The bar is suppressed when stderr is piped and
		// flushed to its 100% state before the result is printed so the final
		// line is never lost.
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
			return fmt.Errorf("%s: %s", i18n.T("argon2id.error.derive_failed"), result.Error)
		}

		if argon2PipeOut {
			if err := util.WriteHexLine(os.Stdout, result.Salt); err != nil {
				return err
			}
			if err := util.WriteHexLine(os.Stdout, result.Data); err != nil {
				return err
			}
		} else {
			emitArgon2Text(result)
		}
		util.WipeBytes(result.Data)
		util.WipeBytes(result.Salt)
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

// emitArgon2Text prints the human-readable output with the derived key in full.
func emitArgon2Text(r kdf.KDFResult) {
	fmt.Println(i18n.TWithData("argon2id.output.algorithm", map[string]interface{}{
		"Memory":      argon2MemoryMB,
		"Iterations":  r.Iterations,
		"Parallelism": argon2Parallelism,
	}))
	fmt.Println(i18n.TWithData("argon2id.output.salt_base64", map[string]interface{}{
		"Salt": base64.StdEncoding.EncodeToString(r.Salt),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.salt_hex", map[string]interface{}{
		"Salt": hex.EncodeToString(r.Salt),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.key_hex", map[string]interface{}{
		"Key": hex.EncodeToString(r.Data),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.key_base64", map[string]interface{}{
		"Key": base64.StdEncoding.EncodeToString(r.Data),
	}))
	fmt.Println(i18n.TWithData("argon2id.output.key_length", map[string]interface{}{
		"Bits": len(r.Data) * 8,
	}))
	fmt.Println(i18n.TWithData("argon2id.output.processing_time", map[string]interface{}{
		"Ms": r.ProcessingTime,
	}))
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		argon2idCmd.Short = i18n.T("argon2id.short")
		argon2idCmd.Long = i18n.T("argon2id.long")
	})

	// The password is only ever read interactively from a terminal with echo
	// disabled; there is no plaintext password flag.
	argon2idCmd.Flags().BoolVar(&argon2Pipe, "pipe", false, i18n.T("argon2id.flag.pipe"))
	argon2idCmd.Flags().BoolVar(&argon2PipeOut, "pipe-out", false, i18n.T("argon2id.flag.pipe_out"))
	argon2idCmd.Flags().StringVar(&argon2Salt, "salt", "", i18n.T("argon2id.flag.salt"))
	argon2idCmd.Flags().IntVar(&argon2Iterations, "iterations", 3, i18n.T("argon2id.flag.iterations"))
	argon2idCmd.Flags().IntVar(&argon2MemoryMB, "memory", 64, i18n.T("argon2id.flag.memory"))
	argon2idCmd.Flags().IntVar(&argon2Parallelism, "parallelism", 1, i18n.T("argon2id.flag.parallelism"))
	argon2idCmd.Flags().IntVar(&argon2KeyLength, "key-length", 64, i18n.T("argon2id.flag.key_length"))
	rootCmd.AddCommand(argon2idCmd)
}
