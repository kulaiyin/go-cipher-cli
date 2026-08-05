package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/hintpool"
	"go-cipher-cli/internal/i18n"
)

// questionPoolConfig is the default question-pool config path, shared by the
// key-derive / data-cipher question-answer flows via localizedConfigPath. The
// shipped pools are embedded in the binary and matched by base file name; the
// on-disk file is only a fallback for custom pools and tests.
var questionPoolConfig = "configs/hint-word-pools_en.json"

// readQuestionPool returns the question-pool JSON bytes for the requested path,
// preferring the embedded copy when the file name is one of the shipped pools.
func readQuestionPool(path string) ([]byte, error) {
	if data, err := hintpool.FS.ReadFile(filepath.Base(path)); err == nil {
		return data, nil
	}
	return os.ReadFile(path)
}

// loadFormSteps reads the question-pool config file: a nested JSON array
// where the outer array is the steps and the inner arrays are questions.
func loadFormSteps(path string) ([][]form.Step, error) {
	data, err := readQuestionPool(path)
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
	if _, err := hintpool.FS.ReadFile(filepath.Base(candidate)); err == nil {
		return candidate
	}
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return questionPoolConfig
}
