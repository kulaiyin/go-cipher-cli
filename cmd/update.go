package cmd

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/update"
)

var (
	updateCheckOnly bool
)

var updateCmd = &cobra.Command{
	Use:   "update [--check]",
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

		fmt.Print(i18n.T("update.confirm_prompt") + " ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" && answer != "yes" && answer != "YES" {
			fmt.Println(i18n.T("update.cancelled"))
			return nil
		}

		fmt.Println(i18n.T("update.downloading"))
		if err := update.DoUpdate(info, runtime.GOOS, runtime.GOARCH); err != nil {
			// The install directory (e.g. /usr/bin) is not writable. Ask the
			// user for consent before elevating with sudo.
			var privErr *update.PrivilegeRequiredError
			if errors.As(err, &privErr) {
				fmt.Println(i18n.TWithData("update.privilege_prompt", map[string]interface{}{
					"Path": privErr.ExecPath,
				}))
				fmt.Print(i18n.T("update.privilege_confirm") + " ")
				var answer string
				fmt.Scanln(&answer)
				if answer != "y" && answer != "Y" && answer != "yes" && answer != "YES" {
					fmt.Println(i18n.T("update.privilege_declined"))
					return nil
				}
				if err := update.InstallWithSudo(privErr.StagingPath, privErr.ExecPath); err != nil {
					return fmt.Errorf("%s: %w", i18n.T("update.error.update_failed"), err)
				}
			} else {
				return fmt.Errorf("%s: %w", i18n.T("update.error.update_failed"), err)
			}
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
	})

	updateCmd.Flags().BoolVar(&updateCheckOnly, "check", false, "")

	rootCmd.AddCommand(updateCmd)
}
