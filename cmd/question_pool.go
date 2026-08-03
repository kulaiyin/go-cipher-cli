package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/i18n"
)

// questionPoolConfig is the default question-pool config path, shared by the
// key-derive / data-cipher question-answer flows via localizedConfigPath.
var questionPoolConfig = "configs/hint-word-pools_en.json"

// loadFormSteps reads the question-pool config file: a nested JSON array
// where the outer array is the steps and the inner arrays are questions.
func loadFormSteps(path string) ([][]form.Step, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("question_pool.error.load_failed"), err)
	}
	var steps [][]form.Step
	if err := json.Unmarshal(data, &steps); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("question_pool.error.invalid_config"), err)
	}
	if len(steps) == 0 {
		return nil, errors.New(i18n.T("question_pool.error.empty_config"))
	}
	for i, step := range steps {
		if len(step) == 0 {
			return nil, fmt.Errorf("%s: %s", i18n.T("question_pool.error.empty_config"), i18n.TWithData("question_pool.error.step", map[string]interface{}{"Step": i + 1}))
		}
		for j, s := range step {
			if s.ID == "" {
				return nil, fmt.Errorf("%s: %s", i18n.T("question_pool.error.invalid_config"), i18n.TWithData("question_pool.error.question", map[string]interface{}{"Step": i + 1, "Index": j + 1}))
			}
		}
	}
	return steps, nil
}

// localizedConfigPath returns the config path matching the current i18n language, falling back to the default.
func localizedConfigPath() string {
	lang := i18n.CurrentLanguage()
	if lang == "" || lang == "en" {
		return questionPoolConfig
	}
	candidate := strings.TrimSuffix(questionPoolConfig, "_en.json") + "_" + lang + ".json"
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return questionPoolConfig
}
