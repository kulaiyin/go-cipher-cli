package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/i18n"
)

var tuiDemoConfig string

// loadFormSteps reads the question-pool config file: a nested JSON array
// where the outer array is the steps and the inner arrays are questions.
func loadFormSteps(path string) ([][]form.Step, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("tui_demo.error.load_failed"), err)
	}
	var steps [][]form.Step
	if err := json.Unmarshal(data, &steps); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("tui_demo.error.invalid_config"), err)
	}
	if len(steps) == 0 {
		return nil, errors.New(i18n.T("tui_demo.error.empty_config"))
	}
	for i, step := range steps {
		if len(step) == 0 {
			return nil, fmt.Errorf("%s: %s", i18n.T("tui_demo.error.empty_config"), i18n.TWithData("tui_demo.error.step", map[string]interface{}{"Step": i + 1}))
		}
		for j, s := range step {
			if s.ID == "" {
				return nil, fmt.Errorf("%s: %s", i18n.T("tui_demo.error.invalid_config"), i18n.TWithData("tui_demo.error.question", map[string]interface{}{"Step": i + 1, "Index": j + 1}))
			}
		}
	}
	return steps, nil
}

func runTuiDemo(cmd *cobra.Command, args []string) error {
	steps, err := loadFormSteps(tuiDemoConfig)
	if err != nil {
		return err
	}

	results, err := form.Run(steps)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("tui_demo.error.run_failed"), err)
	}

	// After the program exits (q on the summary screen), print one line per
	// result so scripts can consume the answers.
	for _, r := range results {
		fmt.Println(i18n.TWithData("tui_demo.output.result_line", map[string]interface{}{
			"Step": r.Step, "ID": r.ID, "Content": r.Content, "Answer": r.Answer,
		}))
	}
	return nil
}

var tuiDemoCmd = &cobra.Command{
	Use:   "tui-demo",
	Short: "placeholder",
	Long:  "placeholder",
	RunE:  runTuiDemo,
}

func init() {
	i18n.MustInit("")
	tuiDemoCmd.Flags().StringVar(&tuiDemoConfig, "config", "configs/hint-word-pools.json", i18n.T("tui_demo.flag.config"))
	refreshCmdDescs = append(refreshCmdDescs, func() {
		tuiDemoCmd.Short = i18n.T("tui_demo.short")
		tuiDemoCmd.Long = i18n.T("tui_demo.long")
	})

	rootCmd.AddCommand(tuiDemoCmd)
}
