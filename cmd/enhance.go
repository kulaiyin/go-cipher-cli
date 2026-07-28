package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

var (
	enhancePassword   string
	enhanceSaltSuffix string
	enhanceDomain     string
)

var enhanceCmd = &cobra.Command{
	Use:   "enhance -p <password> [--salt-suffix <suffix>]",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := enhanceDomain
		if domain == "" {
			domain = kdf.DefaultDomain
		}

		subKeyHex, err := kdf.DeriveSubKeyByDomain(enhancePassword, enhanceSaltSuffix, domain)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("enhance.error.derive_failed"), err)
		}

		subKeyBytes, _ := hex.DecodeString(subKeyHex)

		fmt.Println(i18n.T("enhance.output.algorithm"))
		fmt.Printf("Domain:   %s\n", domain)
		if enhanceSaltSuffix != "" {
			fmt.Println(i18n.TWithData("enhance.output.salt_suffix", map[string]interface{}{
				"Suffix": enhanceSaltSuffix,
			}))
		}
		fmt.Println(i18n.TWithData("enhance.output.key_hex", map[string]interface{}{
			"Key": subKeyHex,
		}))
		fmt.Println(i18n.TWithData("enhance.output.key_base64", map[string]interface{}{
			"Key": base64.StdEncoding.EncodeToString(subKeyBytes),
		}))
		fmt.Println(i18n.TWithData("enhance.output.key_length", map[string]interface{}{
			"Bits": len(subKeyBytes) * 8,
		}))
		return nil
	},
}

func init() {
	i18n.Init("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		enhanceCmd.Short = i18n.T("enhance.short")
		enhanceCmd.Long = i18n.T("enhance.long")
	})

	enhanceCmd.Flags().StringVarP(&enhancePassword, "password", "p", "", i18n.T("enhance.flag.password"))
	enhanceCmd.Flags().StringVarP(&enhanceSaltSuffix, "salt-suffix", "s", "", i18n.T("enhance.flag.salt_suffix"))
	enhanceCmd.Flags().StringVar(&enhanceDomain, "domain", "", i18n.T("enhance.flag.domain"))
	_ = enhanceCmd.MarkFlagRequired("password")
	rootCmd.AddCommand(enhanceCmd)
}
