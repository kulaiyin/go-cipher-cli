package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
)

var version = "v0.4.2"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "placeholder",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		versionCmd.Short = i18n.T("version.short")
	})
}
