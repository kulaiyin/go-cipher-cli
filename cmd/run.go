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
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run an interactive demo task",
	Long:  "Run a demo task that prompts for user input, logs progress, and shows a progress bar.",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := GetLogger()

		var action string
		actionPrompt := &survey.Select{
			Message: "Choose the operation:",
			Options: []string{"Encrypt", "Decrypt"},
			Default: "Encrypt",
		}
		if err := survey.AskOne(actionPrompt, &action, survey.WithValidator(survey.Required)); err != nil {
			return err
		}

		var target string
		targetPrompt := &survey.Input{
			Message: "Enter the target name:",
			Help:    "This can be a file, key, or identifier used for the demo operation.",
		}
		if err := survey.AskOne(targetPrompt, &target, survey.WithValidator(survey.Required)); err != nil {
			return err
		}

		logger.Info("starting demo operation", zap.String("action", action), zap.String("target", target))
		fmt.Println("Processing...")

		p := mpb.New(mpb.WithOutput(os.Stdout), mpb.WithWidth(60))
		bar := p.New(int64(100), mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding(" ").Rbound("]"),
			mpb.PrependDecorators(decor.Name("Progress:"), decor.Percentage()),
		)

		for i := 0; i < 100; i++ {
			time.Sleep(20 * time.Millisecond)
			bar.Increment()
		}
		p.Wait()

		logger.Info("demo operation finished", zap.String("action", action), zap.String("target", target))
		fmt.Printf("Operation %s completed for %s\n", action, target)
		return nil
	},
}
