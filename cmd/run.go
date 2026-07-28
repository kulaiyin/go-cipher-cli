package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"go.uber.org/zap"

	"go-cipher-cli/internal/i18n"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger()

		var action string
		actionPrompt := &survey.Select{
			Message: i18n.T("run.prompt.operation"),
			Options: []string{"Encrypt", "Decrypt"},
			Default: "Encrypt",
		}
		if err := survey.AskOne(actionPrompt, &action, survey.WithValidator(survey.Required)); err != nil {
			return err
		}

		var target string
		targetPrompt := &survey.Input{
			Message: i18n.T("run.prompt.target_name"),
			Help:    i18n.T("run.prompt.target_help"),
		}
		if err := survey.AskOne(targetPrompt, &target, survey.WithValidator(survey.Required)); err != nil {
			return err
		}

		logger.Info("starting demo operation", zap.String("action", action), zap.String("target", target))
		fmt.Println(i18n.T("run.output.processing"))

		p := mpb.New(mpb.WithOutput(os.Stdout), mpb.WithWidth(60))
		bar := p.New(int64(100), mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding(" ").Rbound("]"),
			mpb.PrependDecorators(decor.Name(i18n.T("run.output.progress")), decor.Percentage()),
		)

		for i := 0; i < 100; i++ {
			time.Sleep(20 * time.Millisecond)
			bar.Increment()
		}
		p.Wait()

		logger.Info("demo operation finished", zap.String("action", action), zap.String("target", target))
		fmt.Println(i18n.TWithData("run.output.completed", map[string]interface{}{
			"Action": action,
			"Target": target,
		}))
		return nil
	},
}

func init() {
	i18n.Init("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		runCmd.Short = i18n.T("run.short")
		runCmd.Long = i18n.T("run.long")
	})
	rootCmd.AddCommand(runCmd)
}
