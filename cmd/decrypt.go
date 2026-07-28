package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/i18n"
)

var decryptPasswords []string

var decryptCmd = &cobra.Command{
	Use:   "decrypt [input file]",
	Short: "placeholder",
	Long:  "placeholder",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		buf, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("decrypt.error.read_input"), err)
		}
		parsed, err := container.ExtractDecryptedData(buf)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("decrypt.error.parse_container"), err)
		}

		pt, err := aesgcm.DecryptWithPassword(parsed.EncryptedData, parsed.SaltSeed, decryptPasswords)
		if err != nil {
			// Strip the trailing punctuation the internal package adds for nicer UX.
			msg := err.Error()
			msg = strings.TrimRight(msg, "!")
			return fmt.Errorf("%s: %s", i18n.T("decrypt.error.decrypt_failed"), msg)
		}

		outPath := strings.TrimSuffix(inputPath, ".enc")
		if outPath == inputPath {
			outPath = inputPath + ".dec"
		}
		if err := os.WriteFile(outPath, pt, 0o644); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("decrypt.error.write_output"), err)
		}
		fmt.Println(i18n.TWithData("decrypt.output.success", map[string]interface{}{
			"Size": len(pt),
			"Path": outPath,
		}))
		return nil
	},
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		decryptCmd.Short = i18n.T("decrypt.short")
		decryptCmd.Long = i18n.T("decrypt.long")
	})

	decryptCmd.Flags().StringSliceVarP(&decryptPasswords, "password", "p", nil, i18n.T("decrypt.flag.password"))
	_ = decryptCmd.MarkFlagRequired("password")
	rootCmd.AddCommand(decryptCmd)
}
