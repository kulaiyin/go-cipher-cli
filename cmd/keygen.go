package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/fusion"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

var (
	keygenPasswords  []string
	keygenSalt       string
	keygenHashLength int
	keygenShowSalt   bool
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		salt := keygenSalt
		if salt == "" {
			salt = kdf.GenerateSalt(64) // 64 bytes -> 128 hex
			if keygenShowSalt {
				fmt.Println(i18n.TWithData("keygen.output.salt_only", map[string]interface{}{
					"Salt": salt,
				}))
			} else {
				fmt.Println(i18n.TWithData("keygen.output.salt_auto", map[string]interface{}{
					"Salt": salt,
				}))
			}
		}
		saltBytes, err := hex.DecodeString(salt)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("keygen.error.salt_hex"), err)
		}

		res := kdf.Argon2(joinPasswords(salt, keygenPasswords), kdf.Argon2Config{
			Salt:        saltBytes,
			Iterations:  3,
			MemorySize:  64 * 1024, // 64 MiB
			Parallelism: 4,
			HashLength:  keygenHashLength,
		})
		if !res.Success {
			return fmt.Errorf("%s: %s", i18n.T("keygen.error.derive_failed"), res.Error)
		}

		keyBytes, _ := hex.DecodeString(res.Data)
		fmt.Println(i18n.TWithData("keygen.output.key_hex", map[string]interface{}{"Key": res.Data}))
		fmt.Println(i18n.TWithData("keygen.output.key_base64", map[string]interface{}{"Key": base64.StdEncoding.EncodeToString(keyBytes)}))
		fmt.Println(i18n.TWithData("keygen.output.iterations", map[string]interface{}{"Count": res.Iterations}))
		fmt.Println(i18n.TWithData("keygen.output.hash_length", map[string]interface{}{"Len": res.HashLength}))
		fmt.Println(i18n.TWithData("keygen.output.processing_time", map[string]interface{}{"Ms": res.ProcessingTime}))
		return nil
	},
}

// joinPasswords turns a password list into the single input fed to argon2: a single password
// is used as-is; multiple passwords are fused via fusion.ComputeFinalPassword (normalize + fuse).
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
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		keygenCmd.Short = i18n.T("keygen.short")
		keygenCmd.Long = i18n.T("keygen.long")
	})

	keygenCmd.Flags().StringSliceVarP(&keygenPasswords, "password", "p", nil, i18n.T("keygen.flag.password"))
	keygenCmd.Flags().StringVar(&keygenSalt, "salt", "", i18n.T("keygen.flag.salt"))
	keygenCmd.Flags().IntVar(&keygenHashLength, "hash-length", 32, i18n.T("keygen.flag.hash_length"))
	keygenCmd.Flags().BoolVar(&keygenShowSalt, "show-salt", false, i18n.T("keygen.flag.show_salt"))
	_ = keygenCmd.MarkFlagRequired("password")
	rootCmd.AddCommand(keygenCmd)
}
