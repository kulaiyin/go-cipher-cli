package cmd

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"go-cipher-cli/internal/i18n"
)

var (
	cfgFile  string
	logLevel string
	lang     string
	logger   *zap.Logger

	// refreshCmdDescs is populated by each command's init() and invoked from
	// initConfig() after i18n language is resolved. This ensures Short/Long
	// descriptions are translated based on --lang / LANG, not the auto-detected
	// system locale (which would still be active during init()).
	refreshCmdDescs []func()

	rootCmd = &cobra.Command{
		Use:   "go-cipher-cli",
		Short: "A simple Go CLI with configuration, logging, prompts, and progress",
		Long: `go-cipher-cli is a CLI demo project using Cobra, Viper, Zap, Survey, and MPB.
It demonstrates configuration loading, structured logging, interactive prompts, and progress bars.`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Replace default help command with i18n-aware version.
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: i18n.T("help.short"),
		Long:  i18n.T("help.long"),
		Run: func(c *cobra.Command, args []string) {
			cmd, _, e := c.Root().Find(args)
			if cmd == nil || e != nil {
				c.Printf("Unknown help topic %#q\n", args)
				_ = c.Root().Usage()
			} else {
				cmd.InitDefaultHelpFlag()
				_ = cmd.Help()
			}
		},
	})

	// Replace default completion command with i18n-aware version.
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	compCmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: i18n.T("completion.short"),
		Long:  i18n.T("completion.long"),
	}
	compCmd.AddCommand(
		&cobra.Command{
			Use:   "bash",
			Short: "Generate bash completion script",
			Run: func(c *cobra.Command, args []string) {
				_ = c.Root().GenBashCompletion(c.OutOrStdout())
			},
		},
		&cobra.Command{
			Use:   "zsh",
			Short: "Generate zsh completion script",
			Run: func(c *cobra.Command, args []string) {
				_ = c.Root().GenZshCompletion(c.OutOrStdout())
			},
		},
		&cobra.Command{
			Use:   "fish",
			Short: "Generate fish completion script",
			Run: func(c *cobra.Command, args []string) {
				_ = c.Root().GenFishCompletion(c.OutOrStdout(), true)
			},
		},
		&cobra.Command{
			Use:   "powershell",
			Short: "Generate powershell completion script",
			Run: func(c *cobra.Command, args []string) {
				_ = c.Root().GenPowerShellCompletionWithDesc(c.OutOrStdout())
			},
		},
	)
	rootCmd.AddCommand(compCmd)

	// Register refresh callback so built-in command Short/Long and root
	// flag usages stay in sync when language changes.
	refreshCmdDescs = append(refreshCmdDescs, func() {
		for _, sub := range rootCmd.Commands() {
			switch sub.Name() {
			case "help":
				sub.Short = i18n.T("help.short")
				sub.Long = i18n.T("help.long")
			case "completion":
				sub.Short = i18n.T("completion.short")
				sub.Long = i18n.T("completion.long")
			}
		}

		// Refresh root flag usages (set at init time, stale after --lang).
		if f := rootCmd.PersistentFlags().Lookup("config"); f != nil {
			f.Usage = i18n.T("global.flag.config")
		}
		if f := rootCmd.PersistentFlags().Lookup("lang"); f != nil {
			f.Usage = i18n.T("global.flag.lang")
		}
		if f := rootCmd.PersistentFlags().Lookup("log-level"); f != nil {
			f.Usage = i18n.T("global.flag.log_level")
		}
		if f := rootCmd.Flags().Lookup("help"); f != nil {
			f.Usage = i18n.TWithData("global.flag.help", map[string]interface{}{
				"Command": "go-cipher-cli",
			})
		}
	})

	// Wrap the default help function so that hardcoded pflag text like
	// "(default ...)" is replaced with the localized equivalent.
	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		var buf bytes.Buffer
		oldOut := c.OutOrStdout()
		c.SetOut(&buf)
		defaultHelp(c, args)
		c.SetOut(oldOut)

		output := buf.String()
		defLabel := i18n.T("global.label.default")
		output = strings.ReplaceAll(output, "(default ", "("+defLabel+" ")
		fmt.Fprint(oldOut, output)
	})

	// Pre-register help flag so Cobra's InitDefaultHelpFlag (which checks
	// if the flag already exists) won't overwrite it with an English default.
	rootCmd.Flags().BoolP("help", "h", false, i18n.TWithData("global.flag.help", map[string]interface{}{
		"Command": "go-cipher-cli",
	}))

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", i18n.T("global.flag.config"))
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", i18n.T("global.flag.log_level"))
	rootCmd.PersistentFlags().StringVar(&lang, "lang", "", i18n.T("global.flag.lang"))
	// rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	viper.SetEnvPrefix("GOCIPHER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("log.level", "info")

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.go-cipher-cli")
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Failed to read config: %v\n", err)
		}
	}

	logLevel = viper.GetString("log.level")

	var err error
	logger, err = newZapLogger(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// Initialize i18n (first call loads translations, subsequent are no-op).
	if err := i18n.Init(""); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize i18n: %v\n", err)
		os.Exit(1)
	}

	// Resolve language: --lang flag > config file > GOCIPHER_LANG env > LANG > "en"
	resolved := lang
	if resolved == "" {
		resolved = viper.GetString("lang")
	}
	if resolved == "" {
		resolved = os.Getenv("GOCIPHER_LANG")
	}
	if resolved != "" {
		i18n.SetLanguage(resolved)
	}

	// Re-apply all command descriptions now that the language is final.
	for _, fn := range refreshCmdDescs {
		fn()
	}
}

func newZapLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	return config.Build()
}

func GetLogger() *zap.Logger {
	if logger == nil {
		var err error
		logger, err = newZapLogger(logLevel)
		if err != nil {
			panic(err)
		}
	}
	return logger
}
