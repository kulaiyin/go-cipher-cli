package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/container"
)

var decryptPasswords []string

var decryptCmd = &cobra.Command{
	Use:   "decrypt [input file]",
	Short: "Decrypt a container produced by 'encrypt' or the web tool",
	Long: `Decrypt an AES-256-GCM container. The salt is read from the container, so
only the password(s) are required. An auth-tag mismatch (wrong password) is
reported as a decryption failure.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		buf, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("read input: %w", err)
		}
		parsed, err := container.ExtractDecryptedData(buf)
		if err != nil {
			return fmt.Errorf("parse container: %w", err)
		}

		pt, err := aesgcm.DecryptWithPassword(parsed.EncryptedData, parsed.SaltSeed, decryptPasswords)
		if err != nil {
			// Strip the trailing punctuation the internal package adds for nicer UX.
			msg := err.Error()
			msg = strings.TrimRight(msg, "!")
			return fmt.Errorf("decrypt: %s", msg)
		}

		outPath := strings.TrimSuffix(inputPath, ".enc")
		if outPath == inputPath {
			outPath = inputPath + ".dec"
		}
		if err := os.WriteFile(outPath, pt, 0o644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Printf("Decrypted %d bytes -> %s\n", len(pt), outPath)
		return nil
	},
}

func init() {
	decryptCmd.Flags().StringSliceVarP(&decryptPasswords, "password", "p", nil, "password (repeatable)")
	_ = decryptCmd.MarkFlagRequired("password")
	// rootCmd.AddCommand(decryptCmd)
}

// guard against unused import in case future edits drop an error use.
var _ = errors.New
