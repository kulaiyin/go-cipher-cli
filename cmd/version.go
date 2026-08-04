package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
)

// version is the CLI's version string. goreleaser overrides it at build time
// via -ldflags "-X go-cipher-cli/cmd.version={{ .Tag }}", so released binaries
// report the git tag. The default here covers local `go build`/`go test` runs.
var version = "v0.7.2"

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
