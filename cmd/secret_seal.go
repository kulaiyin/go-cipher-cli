package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"go-cipher-cli/internal/diceware"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/seal"
)

var (
	secretSealMode      string
	secretSealK1        string
	secretSealPassword  string
	secretSealHint      string
	secretSealMusclePw  string
	secretSealOutputDir string
	secretSealInputDir  string
	secretSealFallback  bool
	secretSealNumWords  int
)

var secretSealCmd = &cobra.Command{
	Use:   "secret-seal",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSecretSeal()
	},
}

func runSecretSeal() error {
	// Resolve mode.
	mode := secretSealMode
	if mode == "" {
		if isStdinTerminal() {
			modeOpts := []struct {
				value string
				label string
			}{
				{"encrypt", i18n.T("secret_seal.option.encrypt")},
				{"decrypt", i18n.T("secret_seal.option.decrypt")},
			}
			modeLabels := make([]string, len(modeOpts))
			modeLabelToVal := make(map[string]string, len(modeOpts))
			for i, o := range modeOpts {
				modeLabels[i] = o.label
				modeLabelToVal[o.label] = o.value
			}
			var chosen string
			if err := survey.AskOne(&survey.Select{
				Message: i18n.T("secret_seal.prompt.mode"),
				Options: modeLabels,
			}, &chosen, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
			mode = modeLabelToVal[chosen]
		} else {
			return fmt.Errorf("%s", i18n.T("secret_seal.error.mode_required"))
		}
	}
	if mode != "encrypt" && mode != "decrypt" {
		return fmt.Errorf("%s", i18n.TWithData("secret_seal.error.invalid_mode", map[string]interface{}{
			"Mode": mode,
		}))
	}

	switch mode {
	case "encrypt":
		return runSeal()
	case "decrypt":
		return runUnseal()
	}
	return nil
}

func runSeal() error {
	// Resolve the secret P to protect.
	p := secretSealPassword
	if p == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("secret_seal.error.password_required"))
		}
		if err := survey.AskOne(&survey.Password{
			Message: i18n.T("secret_seal.prompt.password"),
		}, &p, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
	}

	// Resolve K1 (Diceware passphrase).
	k1 := secretSealK1
	if k1 == "" {
		if isStdinTerminal() {
			genK1 := false
			if err := survey.AskOne(&survey.Confirm{
				Message: i18n.T("secret_seal.prompt.generate_k1"),
				Default: true,
			}, &genK1); err != nil {
				return err
			}
			if genK1 {
				nw := secretSealNumWords
				if nw <= 0 {
					nw = 7
				}
				res, err := diceware.GeneratePassphrase(nw, diceware.SepNone)
				if err != nil {
					return fmt.Errorf("%s", i18n.TWithData("secret_seal.error.generate_k1_failed", map[string]interface{}{"Err": err}))
				}
				k1 = res.Passphrase
				fmt.Println()
				fmt.Println(i18n.TWithData("secret_seal.output.k1_generated", map[string]interface{}{
					"K1": k1,
				}))
				fmt.Println(i18n.T("secret_seal.output.k1_warning"))
				fmt.Println()
			} else {
				if err := survey.AskOne(&survey.Password{
					Message: i18n.T("secret_seal.prompt.k1"),
				}, &k1, survey.WithValidator(i18nRequired())); err != nil {
					return err
				}
			}
		} else {
			// Non-interactive: auto-generate K1.
			nw := secretSealNumWords
			if nw <= 0 {
				nw = 7
			}
			res, err := diceware.GeneratePassphrase(nw, diceware.SepNone)
			if err != nil {
				return fmt.Errorf("%s", i18n.TWithData("secret_seal.error.generate_k1_failed", map[string]interface{}{"Err": err}))
			}
			k1 = res.Passphrase
			fmt.Fprintln(os.Stderr, i18n.TWithData("secret_seal.output.k1_generated", map[string]interface{}{
				"K1": k1,
			}))
			fmt.Fprintln(os.Stderr, i18n.T("secret_seal.output.k1_warning"))
		}
	}

	// Resolve hint (optional).
	hint := secretSealHint
	if hint == "" && isStdinTerminal() {
		var useHint bool
		if err := survey.AskOne(&survey.Confirm{
			Message: i18n.T("secret_seal.prompt.use_hint"),
			Default: false,
		}, &useHint); err != nil {
			return err
		}
		if useHint {
			survey.AskOne(&survey.Input{
				Message: i18n.T("secret_seal.prompt.hint"),
			}, &hint)
		}
	}

	// Resolve muscle password.
	musclePw := secretSealMusclePw
	if musclePw == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("secret_seal.error.muscle_pw_required"))
		}
		if err := survey.AskOne(&survey.Password{
			Message: i18n.T("secret_seal.prompt.muscle_pw"),
		}, &musclePw, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
	}

	// Resolve output directory.
	outputDir := secretSealOutputDir
	if outputDir == "" {
		if isStdinTerminal() {
			if err := survey.AskOne(&survey.Input{
				Message: i18n.T("secret_seal.prompt.output_dir"),
				Default: "./seal-vault",
			}, &outputDir, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
		} else {
			outputDir = "./seal-vault"
		}
	}

	if err := seal.Seal(k1, musclePw, p, hint, outputDir); err != nil {
		return fmt.Errorf("%s", i18n.TWithData("secret_seal.error.seal_failed", map[string]interface{}{"Err": err}))
	}

	fmt.Println(i18n.TWithData("secret_seal.output.seal_success", map[string]interface{}{
		"Dir": outputDir,
	}))
	fmt.Println(i18n.T("secret_seal.output.seal_files"))
	fmt.Printf("  %s/encrypt-d.dat\n", outputDir)
	fmt.Printf("  %s/encrypt-k.dat\n", outputDir)
	fmt.Printf("  %s/shares/share-1.dat ... share-5.dat\n", outputDir)
	fmt.Println()
	fmt.Println(i18n.T("secret_seal.output.seal_next_steps"))
	return nil
}

func runUnseal() error {
	// Resolve input directory.
	inputDir := secretSealInputDir
	if inputDir == "" {
		if isStdinTerminal() {
			if err := survey.AskOne(&survey.Input{
				Message: i18n.T("secret_seal.prompt.input_dir"),
				Default: "./seal-vault",
			}, &inputDir, survey.WithValidator(i18nRequired())); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("%s", i18n.T("secret_seal.error.input_dir_required"))
		}
	}

	// Determine unseal path: explicit flags first, then interactive choice.
	useFallback := secretSealFallback
	hasExplicitPath := secretSealK1 != "" || secretSealMusclePw != ""

	if !hasExplicitPath && isStdinTerminal() {
		// Interactive: let the user choose the recovery method.
		pathOpts := []struct {
			value string
			label string
		}{
			{"k1", i18n.T("secret_seal.option.unseal_k1")},
			{"muscle", i18n.T("secret_seal.option.unseal_muscle")},
		}
		pathLabels := make([]string, len(pathOpts))
		pathLabelToVal := make(map[string]string, len(pathOpts))
		for i, o := range pathOpts {
			pathLabels[i] = o.label
			pathLabelToVal[o.label] = o.value
		}
		var chosen string
		if err := survey.AskOne(&survey.Select{
			Message: i18n.T("secret_seal.prompt.unseal_path"),
			Options: pathLabels,
		}, &chosen, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
		useFallback = pathLabelToVal[chosen] == "muscle"
	} else if !hasExplicitPath {
		return fmt.Errorf("%s", i18n.T("secret_seal.error.unseal_path_required"))
	}

	if useFallback || secretSealMusclePw != "" {
		return runUnsealFallback(inputDir)
	}
	return runUnsealPrimary(inputDir)
}

func runUnsealPrimary(inputDir string) error {
	k1 := secretSealK1
	if k1 == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("secret_seal.error.k1_required"))
		}
		if err := survey.AskOne(&survey.Password{
			Message: i18n.T("secret_seal.prompt.k1"),
		}, &k1, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
	}

	// Show the hint if available.
	showHint(inputDir)

	p, err := seal.UnsealPrimary(k1, inputDir)
	if err != nil {
		return fmt.Errorf("%s", i18n.TWithData("secret_seal.error.unseal_failed", map[string]interface{}{"Err": err}))
	}
	printUnsealed(p)
	return nil
}

func runUnsealFallback(inputDir string) error {
	musclePw := secretSealMusclePw
	if musclePw == "" {
		if !isStdinTerminal() {
			return fmt.Errorf("%s", i18n.T("secret_seal.error.muscle_pw_required"))
		}
		// Show the hint before asking for muscle password.
		showHint(inputDir)
		if err := survey.AskOne(&survey.Password{
			Message: i18n.T("secret_seal.prompt.muscle_pw"),
		}, &musclePw, survey.WithValidator(i18nRequired())); err != nil {
			return err
		}
	}

	p, err := seal.UnsealFallback(musclePw, inputDir)
	if err != nil {
		return fmt.Errorf("%s", i18n.TWithData("secret_seal.error.unseal_failed", map[string]interface{}{"Err": err}))
	}
	printUnsealed(p)
	return nil
}

func printUnsealed(p string) {
	fmt.Println(i18n.T("secret_seal.output.unseal_success"))
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println(p)
	fmt.Println(strings.Repeat("-", 40))
}

// showHint reads encrypt-k.dat and prints the hint if present.
func showHint(inputDir string) {
	ek := &seal.EncryptedK1{}
	if err := seal.ReadEncryptedK1(inputDir, ek); err != nil {
		return
	}
	if ek.Hint != "" {
		fmt.Println(i18n.TWithData("secret_seal.output.hint", map[string]interface{}{"Hint": ek.Hint}))
	}
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		secretSealCmd.Short = i18n.T("secret_seal.short")
		secretSealCmd.Long = i18n.T("secret_seal.long")
	})

	secretSealCmd.Flags().StringVar(&secretSealMode, "mode", "", i18n.T("secret_seal.flag.mode"))
	secretSealCmd.Flags().StringVarP(&secretSealK1, "k1", "k", "", i18n.T("secret_seal.flag.k1"))
	secretSealCmd.Flags().StringVar(&secretSealHint, "hint", "", i18n.T("secret_seal.flag.hint"))
	secretSealCmd.Flags().StringVarP(&secretSealPassword, "password", "p", "", i18n.T("secret_seal.flag.password"))
	secretSealCmd.Flags().StringVarP(&secretSealMusclePw, "muscle-password", "m", "", i18n.T("secret_seal.flag.muscle_pw"))
	secretSealCmd.Flags().StringVarP(&secretSealOutputDir, "output", "o", "", i18n.T("secret_seal.flag.output"))
	secretSealCmd.Flags().StringVarP(&secretSealInputDir, "input", "i", "", i18n.T("secret_seal.flag.input"))
	secretSealCmd.Flags().BoolVarP(&secretSealFallback, "fallback", "f", false, i18n.T("secret_seal.flag.fallback"))
	secretSealCmd.Flags().IntVarP(&secretSealNumWords, "num-words", "n", 7, i18n.T("secret_seal.flag.num_words"))
	rootCmd.AddCommand(secretSealCmd)
}
