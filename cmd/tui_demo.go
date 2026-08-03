package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/password"
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

// localizedConfigPath returns the config path matching the current i18n language, falling back to the default.
func localizedConfigPath() string {
	lang := i18n.CurrentLanguage()
	if lang == "" || lang == "en" {
		return tuiDemoConfig
	}
	candidate := strings.TrimSuffix(tuiDemoConfig, "_en.json") + "_" + lang + ".json"
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return tuiDemoConfig
}

func runTuiDemo(cmd *cobra.Command, args []string) error {
	configPath := tuiDemoConfig
	if !cmd.Flags().Changed("config") {
		configPath = localizedConfigPath()
	}
	steps, err := loadFormSteps(configPath)
	if err != nil {
		return err
	}

	// A fresh random salt per run makes the generated password unique, like the
	// web tool's per-visit salt.
	salt := kdf.GenerateSalt(64)
	_, err = form.Run(steps, form.WithFinalPassword(func(results []form.Result) string {
		answers := make([]string, len(results))
		for i, r := range results {
			answers[i] = r.Answer
		}
		pw, err := password.ComputeFinalPassword(salt, answers)
		if err != nil {
			return ""
		}
		return pw
	}))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("tui_demo.error.run_failed"), err)
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
	tuiDemoCmd.Flags().StringVar(&tuiDemoConfig, "config", "configs/hint-word-pools_en.json", i18n.T("tui_demo.flag.config"))
	refreshCmdDescs = append(refreshCmdDescs, func() {
		tuiDemoCmd.Short = i18n.T("tui_demo.short")
		tuiDemoCmd.Long = i18n.T("tui_demo.long")
	})

	rootCmd.AddCommand(tuiDemoCmd)
}
