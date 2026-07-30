package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
		Short: "placeholder",
		Long:  "placeholder",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
)

func Execute() {
	// Resolve i18n language and refresh command descriptions *before* cobra
	// executes. cobra's OnInitialize hook (initConfig, which runs the refresh
	// callbacks) only fires from preRun(), but `--help` and non-runnable
	// commands return flag.ErrHelp before preRun() is reached, so the
	// Short/Long fields would otherwise still be "placeholder" on `--help`.
	// initConfigFromArgs peeks at just the root's global flags (--lang,
	// --config, --log-level) without consuming subcommand args.
	initConfigFromArgs()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// initConfigFromArgs does a minimal pre-parse of the root persistent flags so
// that i18n language resolution and the description-refresh callbacks run before
// cobra dispatches (and before --help is rendered). It deliberately parses into
// a throwaway flag set so it does not disturb cobra's own flag parsing.
func initConfigFromArgs() {
	var preCfg, preLang, preLogLevel string
	fs := pflag.NewFlagSet("preinit", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&preCfg, "config", "", "")
	fs.StringVar(&preLang, "lang", "", "")
	fs.StringVar(&preLogLevel, "log-level", "info", "")
	// Ignore parse errors: unknown flags (subcommand flags, -h, etc.) and bad
	// values are handled properly by cobra's own parse later.
	_ = fs.Parse(os.Args[1:])

	// Mirror initConfig's env/config precedence for the three globals.
	cfgFile = preCfg
	if preLogLevel != "" {
		logLevel = preLogLevel
	}
	lang = preLang

	// Read the config file (if any) so the `lang` setting it may carry is
	// honored even on the --help path, where cobra's OnInitialize (and thus
	// initConfig/viper) never runs. viper is fully (re)loaded later in
	// initConfig; this is a best-effort peek at `lang`/`log.level` only.
	if cfgLang := peekConfigValue(preCfg, "lang"); cfgLang != "" && lang == "" {
		lang = cfgLang
	}

	// Ensure the help command is registered before refreshing. cobra normally
	// adds it during ExecuteC()->InitDefaultHelpCmd(), which runs *after* this
	// pre-parse, so the refresh callback (which walks rootCmd.Commands())
	// would otherwise miss it and leave its Short stale for `--help`.
	// InitDefaultHelpCmd reuses the help command already set via SetHelpCommand.
	rootCmd.InitDefaultHelpCmd()

	applyI18n()
}

// peekConfigValue reads a single key from the config file resolved the same way
// initConfig resolves it (--config file, else ./config or ~/.go-cipher-cli/config,
// yaml by default). It returns "" if no config or the key is absent. Used only
// to surface config-file `lang` on the --help path before viper is fully loaded.
func peekConfigValue(configPath, key string) string {
	v := viper.New()
	v.SetEnvPrefix("GOCIPHER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.go-cipher-cli")
	}
	if err := v.ReadInConfig(); err != nil {
		return ""
	}
	return v.GetString(key)
}

// applyI18n initializes the i18n bundle (idempotent) and re-applies every
// registered command description (Short/Long) and flag usage for the currently
// resolved language. Called both from initConfig (cobra OnInitialize path) and
// from the early initConfigFromArgs (pre-help path).
func applyI18n() {
	if err := i18n.Init(""); err != nil {
		fmt.Fprintln(os.Stderr, i18n.TWithData("global.error.init_i18n", map[string]interface{}{
			"Err": err,
		}))
		os.Exit(1)
	}

	// Resolve language: --lang flag > GOCIPHER_LANG env > LANG env > "en".
	// (Config-file lang is applied here too once viper has read it, but viper
	// is only loaded in initConfig; when applyI18n runs early via
	// initConfigFromArgs the config file has not been read yet. The config
	// value, if any, is picked up when initConfig runs later via OnInitialize.)
	resolved := lang
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
				c.Println(i18n.TWithData("help.unknown_topic", map[string]interface{}{
					"Args": fmt.Sprintf("%#q", args),
				}))
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
		// Root command's own Short/Long.
		rootCmd.Short = i18n.T("root.short")
		rootCmd.Long = i18n.T("root.long")

		for _, sub := range rootCmd.Commands() {
			switch sub.Name() {
			case "help":
				sub.Short = i18n.T("help.short")
				sub.Long = i18n.T("help.long")
			case "completion":
				sub.Short = i18n.T("completion.short")
				sub.Long = i18n.T("completion.long")
				// Refresh the four completion shell subcommands.
				for _, shell := range sub.Commands() {
					switch shell.Name() {
					case "bash":
						shell.Short = i18n.T("completion.bash.short")
					case "zsh":
						shell.Short = i18n.T("completion.zsh.short")
					case "fish":
						shell.Short = i18n.T("completion.fish.short")
					case "powershell":
						shell.Short = i18n.T("completion.powershell.short")
					}
				}
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
		fmt.Fprintln(os.Stderr, i18n.TWithData("global.message.using_config", map[string]interface{}{
			"Path": viper.ConfigFileUsed(),
		}))
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintln(os.Stderr, i18n.TWithData("global.error.read_config", map[string]interface{}{
				"Err": err,
			}))
		}
	}

	logLevel = viper.GetString("log.level")

	var err error
	logger, err = newZapLogger(logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.TWithData("global.error.init_logger", map[string]interface{}{
			"Err": err,
		}))
		os.Exit(1)
	}

	// Fold the config-file `lang` value into the global so applyI18n sees the
	// full precedence (--lang > config file > GOCIPHER_LANG env > LANG).
	if lang == "" {
		lang = viper.GetString("lang")
	}

	// Initialize i18n and refresh command descriptions (also runs early via
	// initConfigFromArgs for the --help path; re-running here is harmless).
	applyI18n()
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
