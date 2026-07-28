package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version = "v0.3.2"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the CLI version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version)
	},
}
