package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/fusion"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/safety"
)

var (
	keygenPasswords  []string
	keygenSalt       string
	keygenHashLength int
	keygenShowSalt   bool
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Derive a key from a salt + passwords (argon2id)",
	Long: `Derive a key from a salt and one or more passwords using argon2id (the
frontend KeyDerivation path). Useful for producing a strong key outside of the
encrypt/decrypt flow, e.g. for configuring other tools.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		salt := keygenSalt
		if salt == "" {
			salt = kdf.GenerateSalt(64) // 64 bytes -> 128 hex
			if keygenShowSalt {
				fmt.Printf("salt: %s\n", salt)
			} else {
				fmt.Printf("salt: %s (auto-generated, pass --salt to reproduce)\n", salt)
			}
		}
		saltBytes, err := hex.DecodeString(salt)
		if err != nil {
			return fmt.Errorf("salt must be hex: %w", err)
		}

		res := kdf.Argon2(joinPasswords(salt, keygenPasswords), kdf.Argon2Config{
			Salt:        saltBytes,
			Iterations:  3,
			MemorySize:  64 * 1024, // 64 MiB (frontend default)
			Parallelism: 4,
			HashLength:  keygenHashLength,
		})
		if !res.Success {
			return fmt.Errorf("derive: %s", res.Error)
		}

		keyBytes, _ := hex.DecodeString(res.Data)
		fmt.Printf("key (hex):      %s\n", res.Data)
		fmt.Printf("key (base64):   %s\n", base64.StdEncoding.EncodeToString(keyBytes))
		fmt.Printf("iterations:     %d\n", res.Iterations)
		fmt.Printf("hash length:    %d bytes\n", res.HashLength)
		fmt.Printf("processing:     %dms\n", res.ProcessingTime)
		return nil
	},
}

// joinPasswords mirrors how the web PasswordGenerationModal turns a password list into the
// single input fed to argon2: a single password is used as-is; multiple passwords are fused
// via fusion.ComputeFinalPassword (normalize + fusePasswords).
func joinPasswords(salt string, pws []string) string {
	if len(pws) == 0 {
		return ""
	}
	if len(pws) == 1 {
		return fusion.NormalizePassword(pws[0])
	}
	return fusion.ComputeFinalPassword(salt, pws)
}

func init() {
	keygenCmd.Flags().StringSliceVarP(&keygenPasswords, "password", "p", nil, "password (repeatable)")
	keygenCmd.Flags().StringVar(&keygenSalt, "salt", "", "128-hex salt (auto-generated if omitted)")
	keygenCmd.Flags().IntVar(&keygenHashLength, "hash-length", 32, "derived key length in bytes")
	keygenCmd.Flags().BoolVar(&keygenShowSalt, "show-salt", false, "print only the salt line when auto-generating")
	_ = keygenCmd.MarkFlagRequired("password")
	rootCmd.AddCommand(keygenCmd)

	_ = safety.GenerateRandomBytes // keep package referenced for future helpers
}
