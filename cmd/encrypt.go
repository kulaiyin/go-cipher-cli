package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/aesgcm"
	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/safety"
)

const containerVersion = 10000

var (
	encryptPasswords []string
	encryptSalt      string
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt [input file]",
	Short: "placeholder",
	Long:  "placeholder",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("encrypt.error.read_input"), err)
		}
		if len(data) == 0 {
			return errors.New(i18n.T("encrypt.error.empty_input"))
		}

		// Generate a salt if none provided.
		salt := encryptSalt
		if salt == "" {
			salt = safety.BytesToHex(safety.GenerateRandomBytes(64))
		}
		if _, err := hex.DecodeString(salt); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("encrypt.error.salt_hex"), err)
		}

		ct, err := aesgcm.EncryptWithPassword(data, salt, encryptPasswords)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("encrypt.error.encrypt_failed"), err)
		}

		buf, err := container.AssembleDownloadData(containerVersion, 0, salt, ct)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("encrypt.error.assemble_container"), err)
		}

		outPath := inputPath + ".enc"
		if err := os.WriteFile(outPath, buf, 0o644); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("encrypt.error.write_output"), err)
		}
		fmt.Println(i18n.TWithData("encrypt.output.success", map[string]interface{}{
			"Size":    len(data),
			"Path":    outPath,
			"Version": containerVersion,
		}))
		return nil
	},
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		encryptCmd.Short = i18n.T("encrypt.short")
		encryptCmd.Long = i18n.T("encrypt.long")
	})

	encryptCmd.Flags().StringSliceVarP(&encryptPasswords, "password", "p", nil, i18n.T("encrypt.flag.password"))
	encryptCmd.Flags().StringVar(&encryptSalt, "salt", "", i18n.T("encrypt.flag.salt"))
	_ = encryptCmd.MarkFlagRequired("password")
	rootCmd.AddCommand(encryptCmd)
}
