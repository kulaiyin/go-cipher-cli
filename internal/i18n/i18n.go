// Package i18n provides internationalization support for go-cipher-cli.
// It wraps github.com/nicksnyder/go-i18n/v2 with a lazy-init singleton and
// convenience helpers for CLI use.
//
// Language detection order:
//  1. Explicit language passed to Init(lang) or SetLanguage(lang)
//  2. LANG environment variable (e.g. "zh_CN.UTF-8" -> "zh")
//  3. Fallback to English
//
// Locale TOML files are embedded via //go:embed so the binary is self-contained.
package i18n

import (
	"embed"
	"os"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed locales/*.toml
var localeFS embed.FS

var (
	once        sync.Once
	initErr     error
	bundle      *i18n.Bundle
	localizer   *i18n.Localizer
	currentLang string
)

// Init initializes the i18n bundle and localizer. Safe to call multiple times.
// If lang is empty, detects from the LANG environment variable.
func Init(lang string) error {
	once.Do(func() {
		bundle = i18n.NewBundle(language.English)
		bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

		// Load all embedded locale TOML files.
		entries, err := localeFS.ReadDir("locales")
		if err != nil {
			initErr = err
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
				continue
			}
			data, err := localeFS.ReadFile("locales/" + entry.Name())
			if err != nil {
				initErr = err
				return
			}
			if _, err := bundle.ParseMessageFileBytes(data, entry.Name()); err != nil {
				initErr = err
				return
			}
		}

		SetLanguage(lang)
	})
	return initErr
}

// SetLanguage switches the localizer to the given language at runtime.
// If lang is empty, detects from the LANG environment variable.
func SetLanguage(lang string) {
	if bundle == nil {
		return
	}
	if lang == "" {
		lang = detectLang()
	}
	localizer = i18n.NewLocalizer(bundle, lang)
	currentLang = lang
}

// CurrentLanguage returns the currently active language tag.
func CurrentLanguage() string {
	if currentLang == "" {
		return "en"
	}
	return currentLang
}

// detectLang reads the LANG environment variable and extracts the language code.
// Returns "en" if LANG is not set.
func detectLang() string {
	l := os.Getenv("LANG")
	if l == "" {
		return "en"
	}
	l = strings.Split(l, ".")[0]
	parts := strings.Split(l, "_")
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "en"
}

// T is a shorthand for translating a message ID with no template data.
func T(messageID string) string {
	s, err := Localize(&i18n.LocalizeConfig{MessageID: messageID})
	if err != nil {
		return messageID
	}
	return s
}

// TWithData translates a message ID with template data.
func TWithData(messageID string, data map[string]interface{}) string {
	s, err := Localize(&i18n.LocalizeConfig{
		MessageID:   messageID,
		TemplateData: data,
	})
	if err != nil {
		return messageID
	}
	return s
}

// Localize wraps i18n.Localizer.Localize with nil-safety.
func Localize(config *i18n.LocalizeConfig) (string, error) {
	if localizer == nil {
		return config.MessageID, nil
	}
	return localizer.Localize(config)
}

// MustLocalize wraps i18n.Localizer.MustLocalize with nil-safety.
func MustLocalize(config *i18n.LocalizeConfig) string {
	if localizer == nil {
		return config.MessageID
	}
	return localizer.MustLocalize(config)
}
