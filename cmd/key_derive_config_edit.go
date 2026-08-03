package cmd

// --use-config-file flow: instead of collecting input/hint/strength from
// flags or interactive prompts, the command writes an annotated YAML template,
// opens it in the user's editor, and loads the edited values. The password is
// kept OUT of the config file (supplied via -p or a hidden prompt) so it never
// lands on disk. The loaded values drive the normal generate derivation;
// restore is untouched.
//
// Field names in the YAML mirror the CLI parameter names exactly (input, hint,
// strength) so the config file is self-documenting.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-cipher-cli/internal/diceware"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/validation"

	"go.yaml.in/yaml/v3"
)

// configFilePath returns the auto-generated config path inside the mntemp
// default directory: <tmp>/mntemp/<name>/<name>_<timestamp>.yaml. The path is
// derived (not user-configurable), so each run gets a fresh, uniquely named
// template that survives the editor loop.
func configFilePath() string {
	dir := filepath.Join(os.TempDir(), "mntemp", mntempDefaultName)
	return filepath.Join(dir, fmt.Sprintf("%s_%s.yaml", mntempDefaultName, time.Now().Format("20060102_150405")))
}

// configFileData is the shape of the edited YAML file. Field names equal the
// key-derive parameter names so the file matches the CLI surface.
// configFileData is the shape of the edited YAML file. Field names equal the
// key-derive parameter names so the file matches the CLI surface. Password is
// deliberately NOT part of the file: it is supplied via -p or a hidden prompt
// so it never lands on disk.
type configFileData struct {
	Input    string `yaml:"input"`
	Hint     string `yaml:"hint"`
	Strength string `yaml:"strength"`
}

// runKeyDeriveWithConfigFile implements the whole --use-config-file flow:
//
//	generate template (annotated, 0600) -> editor loop (edit, confirm,
//	validate; re-edit on failure) -> derive with the loaded values.
//
// Only generate mode is supported; restore keeps its existing behaviour.
func runKeyDeriveWithConfigFile(p *keyDeriveParams) error {
	mode := strings.ToLower(strings.TrimSpace(p.Mode.Value))
	if mode == "" {
		mode = "generate"
	}
	if mode != "generate" {
		return fmt.Errorf("%s", i18n.T("key_derive.config_edit.error_generate_only"))
	}

	path, err := resolveConfigPath(p.ConfigFile, p.Hint.Value)
	if err != nil {
		return err
	}

	data := configFileData{}
	// One reader shared across the loop: a fresh bufio.Reader per confirmation
	// would pre-read buffered piped input and drop it when the Reader is
	// discarded, making the second confirmation see a closed stdin.
	confirmReader := bufio.NewReader(os.Stdin)
	for {
		// No editor is launched (cross-platform): print the config path and
		// let the user open and edit it in their own editor.
		fmt.Println(i18n.TWithData("key_derive.config_edit.prompt_edit_path", map[string]interface{}{
			"Path": path,
		}))
		done, err := confirmConfigEditDone(confirmReader)
		if err != nil {
			return err
		}
		if !done {
			continue // user edits again; the path is re-printed on the next loop
		}

		d, err := loadConfigFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		if err := validateConfigFileData(&d); err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		data = d
		break
	}

	password, err := collectConfigPassword(p)
	if err != nil {
		return err
	}

	input := cleanKeyDeriveText(data.Input)
	password = cleanKeyDeriveText(password)
	hint := data.Hint
	if hint == "" {
		hint = firstNChars(input, 10)
	}

	// The generated recovery config is saved to disk (next to the config file,
	// sharing its timestamp base) and the user is warned it is volatile: the
	// temp dir is wiped on reboot, so it must be saved elsewhere to be able to
	// restore the keys later. An explicit --output still wins.
	if p.Output.Value == "" {
		p.Output.Value = recoveryConfigPath(path)
	}
	if err := runKeyDeriveGenerate(p, input, password, hint, kdf.Strength(data.Strength)); err != nil {
		return err
	}
	fmt.Println(i18n.T("key_derive.config_edit.output_volatile"))
	return nil
}

// recoveryConfigPath derives the recovery config output path from the config
// file path, swapping the extension: default_<ts>.yaml -> default_<ts>.txt.
// Both files then share the same timestamp and directory.
func recoveryConfigPath(configPath string) string {
	return strings.TrimSuffix(configPath, filepath.Ext(configPath)) + ".txt"
}

// collectConfigPassword returns the password used for derivation: the -p flag
// value when provided, otherwise a hidden interactive prompt (TTY only). It
// keeps the password out of the config file entirely.
func collectConfigPassword(p *keyDeriveParams) (string, error) {
	if pw := p.Password.Value; pw != "" {
		if err := validation.ValidateKeyDerivePassword(pw); err != nil {
			return "", err
		}
		return pw, nil
	}
	if !param.IsStdinTerminal() {
		return "", fmt.Errorf("%s", i18n.T("key_derive.config_edit.error_password_required"))
	}
	// Reuse the declarative password field: hidden prompt, same
	// validation rule as the standard generate flow, loops on invalid input.
	field := param.Field{
		PromptType:      param.PromptPassword,
		PromptKeyPrefix: "key_derive",
		Rules:           []param.Rule{{Name: "key_derive_password"}},
	}
	var pw string
	if err := field.Prompt(&pw, "password"); err != nil {
		return "", err
	}
	return pw, nil
}

// resolveConfigPath returns the config file to edit:
//
//   - custom != "" and the file exists: edit it in place (user-provided config)
//   - custom != "" but missing: generate an annotated template there
//   - custom == "": generate under the mntemp default directory
//
// The template is generated only when the file does not already exist, so an
// existing config is never overwritten and a generated template is never
// regenerated during the editor loop.
func resolveConfigPath(custom, hint string) (string, error) {
	path := strings.TrimSpace(custom)
	if path == "" {
		path = configFilePath()
	}
	if _, err := os.Stat(path); err == nil {
		return path, nil // existing file: edit in place
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := writeConfigTemplate(path, hint); err != nil {
		return "", err
	}
	return path, nil
}

// writeConfigTemplate creates the annotated YAML skeleton at path. The comment
// lines come from i18n (so the template language follows the locale) and the
// input example is a freshly generated 8-word Diceware passphrase the user may
// adopt directly as their input.
func writeConfigTemplate(path string, hint string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("key_derive.config_edit.error_mkdir"), err)
		}
	}

	example, err := diceware.GeneratePassphrase(8, diceware.SepSpace)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("key_derive.config_edit.error_example"), err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n", i18n.T("key_derive.config_edit.template_input_warning"))
	fmt.Fprintf(&b, "# %s %s\n", i18n.T("key_derive.config_edit.template_input_example"), example.Passphrase)
	fmt.Fprintf(&b, "input: \"\"\n\n")

	fmt.Fprintf(&b, "# %s\n", i18n.T("key_derive.config_edit.template_hint"))
	if hint == "" {
		fmt.Fprintf(&b, "hint: \"\"\n\n")
	} else {
		// %q produces a double-quoted string valid in YAML for typical hints.
		fmt.Fprintf(&b, "hint: %q\n\n", hint)
	}

	fmt.Fprintf(&b, "# %s: basic | medium | advanced\n", i18n.T("key_derive.config_edit.template_strength"))
	fmt.Fprintf(&b, "strength: \"medium\"\n")

	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// confirmConfigEditDone asks whether the user finished editing. Enter (empty
// line) or y/yes confirm; anything else re-opens the editor. A closed stdin
// with no input aborts instead of looping forever.
func confirmConfigEditDone(reader *bufio.Reader) (bool, error) {
	fmt.Print(i18n.T("key_derive.config_edit.prompt_done"))
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return false, fmt.Errorf("%s", i18n.T("key_derive.config_edit.error_stdin_closed"))
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "", "y", "yes":
		return true, nil
	}
	return false, nil
}

// loadConfigFile parses the edited YAML, rejecting unknown fields so a typo
// (e.g. "pasword") surfaces as an error instead of being silently dropped.
func loadConfigFile(path string) (configFileData, error) {
	f, err := os.Open(path)
	if err != nil {
		return configFileData{}, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var d configFileData
	if err := dec.Decode(&d); err != nil {
		return configFileData{}, fmt.Errorf("%s: %w", i18n.T("key_derive.config_edit.error_parse"), err)
	}
	return d, nil
}

// validateConfigFileData applies the same rules the generate path enforces for
// input, and normalizes strength to its default (medium). Callers re-open the
// editor when this returns an error.
func validateConfigFileData(d *configFileData) error {
	d.Input = strings.TrimSpace(d.Input)
	if d.Input == "" {
		return fmt.Errorf("%s", i18n.T("key_derive.config_edit.error_input_required"))
	}
	if err := validation.ValidateKeyDeriveInput(d.Input); err != nil {
		return err
	}

	d.Strength = strings.TrimSpace(d.Strength)
	if d.Strength == "" {
		d.Strength = "medium"
	}
	switch d.Strength {
	case "basic", "medium", "advanced":
	default:
		return fmt.Errorf("%s", i18n.TWithData("key_derive.config_edit.error_strength_allowed", map[string]interface{}{
			"Value":   d.Strength,
			"Allowed": "basic, medium, advanced",
		}))
	}
	return nil
}
