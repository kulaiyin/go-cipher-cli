package cmd

import (
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
	rootCmd  = &cobra.Command{
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&lang, "lang", "", "display language (en, zh); defaults to LANG env")
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
