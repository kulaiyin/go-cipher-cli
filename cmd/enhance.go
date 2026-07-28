package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/kdf"
)

var (
	enhancePassword   string
	enhanceSaltSuffix string
	enhanceDomain     string
)

var enhanceCmd = &cobra.Command{
	Use:     "enhance -p <密码> [--salt-suffix <后缀>]",
	Aliases: []string{"en"},
	Short:   "将密码转换为 256 位高熵密钥（密码转密钥）",
	Long: `用你记得住的常用密码生成一把 256 位高熵密钥，真正用于加密/认证的
是这把密钥，密码本身只是生成原料。

算法：Argon2id(64MB/3轮/1路并行) + HKDF-Expand(SHA-256) 域分离。
同一组密码 + 盐后缀确定性派生出相同密钥，无法由密钥反推密码。
与 Web 工具 (https://tools.wcheer.com/) 字节级互通。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := enhanceDomain
		if domain == "" {
			domain = kdf.DefaultDomain
		}

		subKeyHex, err := kdf.DeriveSubKeyByDomain(enhancePassword, enhanceSaltSuffix, domain)
		if err != nil {
			return fmt.Errorf("派生失败: %w", err)
		}

		subKeyBytes, _ := hex.DecodeString(subKeyHex)

		fmt.Printf("算法:     Argon2id(64MB/3轮/1路并行) + HKDF-Expand(SHA-256)\n")
		fmt.Printf("Domain:   %s\n", domain)
		if enhanceSaltSuffix != "" {
			fmt.Printf("盐后缀:   %s\n", enhanceSaltSuffix)
		}
		fmt.Printf("密钥(hex):     %s\n", subKeyHex)
		fmt.Printf("密钥(base64):  %s\n", base64.StdEncoding.EncodeToString(subKeyBytes))
		fmt.Printf("密钥长度:      %d 位 (256 bit)\n", len(subKeyBytes)*8)
		return nil
	},
}

func init() {
	enhanceCmd.Flags().StringVarP(&enhancePassword, "password", "p", "", "要转换的密码（必填）")
	enhanceCmd.Flags().StringVar(&enhanceSaltSuffix, "salt-suffix", "", "可选盐后缀（如站点名、设备名），不同后缀派生不同密钥")
	enhanceCmd.Flags().StringVar(&enhanceDomain, "domain", "", "域标签（默认 default-v1，一般不修改）")
	_ = enhanceCmd.MarkFlagRequired("password")
	rootCmd.AddCommand(enhanceCmd)
}
