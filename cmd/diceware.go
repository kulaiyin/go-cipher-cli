package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/diceware"
)

var (
	diceNumWords int
	diceSep      string
)

var dicewareCmd = &cobra.Command{
	Use:   "diceware [-n <词数>] [--sep <分隔符>]",
	Short: "生成 Diceware 助记口令（EFF 词表，7776 词）",
	Long: `用 EFF 大型词表（7776 词）和密码学安全随机掷骰，生成易记但高熵的口令。

随机数来源：crypto/rand (Go CSPRNG)。
每词提供约 12.9 bit 熵，5 词口令约 64.6 bit，8 词口令约 103.4 bit。

与 Web 工具 (https://tools.wcheer.com/) 的 Diceware 生成器同词表、同算法。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		sep := parseSeparator(diceSep)

		result, err := diceware.GeneratePassphrase(diceNumWords, sep)
		if err != nil {
			return fmt.Errorf("生成失败: %w", err)
		}

		fmt.Printf("口令:         %s\n", result.Passphrase)
		fmt.Printf("长度:         %d 字符\n", len(result.Passphrase))
		fmt.Printf("词数:         %d\n", len(result.Rolls))
		fmt.Printf("信息熵:       %.2f bit\n", result.EntropyBits)
		fmt.Printf("可能组合数:   %s\n", diceware.FormatCombinations(result.Combinations))
		fmt.Printf("分隔符:       %s\n", sepDesc(sep))
		fmt.Println()
		fmt.Println("逐词掷骰详情:")
		for i, roll := range result.Rolls {
			fmt.Printf("  %2d. [%s] %s\n", i+1, roll.Dice, roll.Word)
		}
		return nil
	},
}

func parseSeparator(s string) diceware.Separator {
	switch strings.ToLower(s) {
	case "hyphen", "-":
		return diceware.SepHyphen
	case "none", "":
		return diceware.SepNone
	default:
		return diceware.SepSpace
	}
}

func sepDesc(s diceware.Separator) string {
	switch s {
	case diceware.SepHyphen:
		return "连字符 (-)"
	case diceware.SepNone:
		return "无"
	default:
		return "空格"
	}
}

func init() {
	dicewareCmd.Flags().IntVarP(&diceNumWords, "num-words", "n", 5, "单词数量 (1-20)")
	dicewareCmd.Flags().StringVar(&diceSep, "sep", "space", "分隔符: space / hyphen / none")
	rootCmd.AddCommand(dicewareCmd)
}
