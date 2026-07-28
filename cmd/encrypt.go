package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/safety"
)

const containerVersion = 10000

var (
	encryptPasswords []string
	encryptSalt      string
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [input file]",
	Short: "Encrypt a file with AES-256-GCM (frontend-compatible container)",
	Long: `Encrypt a file using the same key-derivation pipeline as the web tool:
argon2id -> HMAC-SHA3-512 -> HKDF-SHA3-512 -> AES-256-GCM.

The salt is stored inside the output container so decryption only needs the
password(s). If --salt is omitted a random one is generated. The output file is
a binary container (version|reserved|salt_seed|length|ciphertext) that the web
tool can also decrypt.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
		if len(data) == 0 {
			return errors.New("input file is empty")
		}

		// Generate a salt if none provided (the web tool always has one from key-derivation).
		salt := encryptSalt
		if salt == "" {
			salt = safety.BytesToHex(safety.GenerateRandomBytes(64))
		}
		if _, err := hex.DecodeString(salt); err != nil {
			return fmt.Errorf("salt must be a hex string: %w", err)
		}

		ct, err := aesgcm.EncryptWithPassword(data, salt, encryptPasswords)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		buf, err := container.AssembleDownloadData(containerVersion, 0, salt, ct)
		if err != nil {
			return fmt.Errorf("assemble container: %w", err)
		}

		outPath := inputPath + ".enc"
		if err := os.WriteFile(outPath, buf, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Printf("Encrypted %d bytes -> %s (salt embedded, version=%d)\n", len(data), outPath, containerVersion)
		return nil
	},
}

func init() {
	encryptCmd.Flags().StringSliceVarP(&encryptPasswords, "password", "p", nil, "password (repeatable, e.g. -p a -p b); order does not matter")
	encryptCmd.Flags().StringVar(&encryptSalt, "salt", "", "optional 128-hex salt seed (auto-generated if omitted)")
	_ = encryptCmd.MarkFlagRequired("password")
	// rootCmd.AddCommand(encryptCmd)
}
