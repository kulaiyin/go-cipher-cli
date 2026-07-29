package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/update"
)

var (
	updateCheckOnly bool
	updateYes       bool
)

var updateCmd = &cobra.Command{
	Use:   "update [--check] [--yes]",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := update.CheckLatest(version, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("update.error.check_failed"), err)
		}

		if info == nil {
			fmt.Println(i18n.TWithData("update.up_to_date", map[string]interface{}{
				"Version": version,
			}))
			return nil
		}

		fmt.Println(i18n.TWithData("update.new_version_available", map[string]interface{}{
			"Current": version,
			"Latest":  info.TagName,
		}))

		if updateCheckOnly {
			return nil
		}

		if !updateYes {
			fmt.Print(i18n.T("update.confirm_prompt") + " ")
			var answer string
			fmt.Scanln(&answer)
			if answer != "y" && answer != "Y" && answer != "yes" && answer != "YES" {
				fmt.Println(i18n.T("update.cancelled"))
				return nil
			}
		}

		fmt.Println(i18n.T("update.downloading"))
		if err := update.DoUpdate(info, runtime.GOOS, runtime.GOARCH); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("update.error.update_failed"), err)
		}

		fmt.Println(i18n.TWithData("update.updated", map[string]interface{}{
			"Version": info.TagName,
		}))
		return nil
	},
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		updateCmd.Short = i18n.T("update.short")
		updateCmd.Long = i18n.T("update.long")
		updateCmd.Flags().Lookup("check").Usage = i18n.T("update.flag.check")
		updateCmd.Flags().Lookup("yes").Usage = i18n.T("update.flag.yes")
	})

	updateCmd.Flags().BoolVar(&updateCheckOnly, "check", false, "")
	updateCmd.Flags().BoolVarP(&updateYes, "yes", "y", false, "")

	rootCmd.AddCommand(updateCmd)
}
