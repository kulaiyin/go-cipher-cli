package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/diceware"
	"go-cipher-cli/internal/i18n"
)

var (
	diceNumWords int
	diceSep      string
)

var dicewareCmd = &cobra.Command{
	Use:   "diceware [-n <num-words>] [--sep <separator>]",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		sep := parseSeparator(diceSep)

		result, err := diceware.GeneratePassphrase(diceNumWords, sep)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("diceware.error.generate_failed"), err)
		}

		fmt.Println(i18n.TWithData("diceware.output.passphrase", map[string]interface{}{
			"Passphrase": result.Passphrase,
		}))
		fmt.Println(i18n.TWithData("diceware.output.length", map[string]interface{}{
			"Len": len(result.Passphrase),
		}))
		fmt.Println(i18n.TWithData("diceware.output.words", map[string]interface{}{
			"Count": len(result.Rolls),
		}))
		fmt.Println(i18n.TWithData("diceware.output.entropy", map[string]interface{}{
			"Bits": fmt.Sprintf("%.2f", result.EntropyBits),
		}))
		fmt.Println(i18n.TWithData("diceware.output.combinations", map[string]interface{}{
			"Combinations": diceware.FormatCombinations(result.Combinations),
		}))
		fmt.Println(i18n.TWithData("diceware.output.separator", map[string]interface{}{
			"Sep": sepDesc(sep),
		}))
		fmt.Println()
		fmt.Println(i18n.T("diceware.output.details_header"))
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
		return i18n.T("diceware.sep.hyphen")
	case diceware.SepNone:
		return i18n.T("diceware.sep.none")
	default:
		return i18n.T("diceware.sep.space")
	}
}

func init() {
	dicewareCmd.Flags().IntVarP(&diceNumWords, "num-words", "n", 5, i18n.T("diceware.flag.num_words"))
	dicewareCmd.Flags().StringVar(&diceSep, "sep", "none", i18n.T("diceware.flag.sep"))
	rootCmd.AddCommand(dicewareCmd)
}
