package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

// recoveryConfig is the JSON shape written by generate and read by restore. It
// carries everything needed to re-derive the same key set on another run.
type recoveryConfig struct {
	Version  string   `json:"version"`
	Strength string   `json:"strength"`
	Salt     string   `json:"salt"`
	UUID     string   `json:"uuid"`
	Hint     string   `json:"hint"`
	HintIDs  []string `json:"hint_ids"`
	UUIDs    []string `json:"uuids"`
}

// buildRecoveryConfig constructs the config from a derivation result. UUIDs is
// populated with the masked (first8 + last8) form of each derived key plus the
// UUID itself (matching the frontend's download format exactly).
func buildRecoveryConfig(r kdf.KeySetResult, hint string, hintIDs []string) recoveryConfig {
	uuids := make([]string, 0, len(r.Keys)+1)
	for _, k := range r.Keys {
		uuids = append(uuids, maskedKey(k))
	}
	// Frontend includes the UUID fingerprint as the 4th element in uuids[]
	// (KeyDerivationForm.vue:860-864).
	uuids = append(uuids, maskedKey(r.UUID))
	return recoveryConfig{
		Version:  keyDeriveKeyDriveVersion,
		Strength: string(r.Strength),
		Salt:     r.SaltSeed,
		UUID:     r.UUID,
		Hint:     hint,
		HintIDs:  hintIDs,
		UUIDs:    uuids,
	}
}

// maskedKey returns the first 8 + last 8 hex chars of a key — the exact format
// ValidateKeyRecovery checks against (no asterisks). Mirrors the frontend's
// processed-key form (KeyDerivationForm.vue:853-856).
func maskedKey(key string) string {
	runes := []rune(key)
	n := len(runes)
	prefixEnd := 8
	if prefixEnd > n {
		prefixEnd = n
	}
	suffixStart := n - 8
	if suffixStart < 0 {
		suffixStart = 0
	}
	return string(runes[:prefixEnd]) + string(runes[suffixStart:])
}

// displayMaskKey matches the frontend's maskKey function
// (KeyDerivationForm.vue:831-839): first 8 chars + (key_length - 16) asterisks
// + last 8 chars. This is the human-readable masking, NOT the fingerprint form.
// For a 128-hex key this produces e.g. "ec9b6b4c****...****a0e127".
func displayMaskKey(key string) string {
	runes := []rune(key)
	n := len(runes)
	if n <= 16 {
		return key
	}
	prefix := string(runes[:8])
	suffix := string(runes[n-8:])
	masked := strings.Repeat("*", n-16)
	return prefix + masked + suffix
}

// parseStrengthLabel maps a strength label (English raw value or legacy
// Chinese frontend label) back to the internal strength value.
func parseStrengthLabel(label string) string {
	switch strings.TrimSpace(label) {
	case "basic", i18n.T("key_derive.parse.legacy_strength_basic"):
		return "basic"
	case "advanced", i18n.T("key_derive.parse.legacy_strength_advanced"):
		return "advanced"
	default:
		return "medium"
	}
}

// formatFrontendRecoveryConfig produces the recovery config in a multilingual
// text+base64 format. Labels are generated with i18n.T() so the output respects
// the CLI locale. The parser accepts English, Chinese, and the current locale's
// labels for backward compatibility.
//
// Format (English shown):
//
//	Derived Keys:
//	Key1: <masked key 1>
//	Key2: <masked key 2>
//	Key3: <masked key 3>
//
//	Config Info:
//	Algorithm: Argon2id + HKDF
//	Website: https://tools.wcheer.com/
//	Hint: <hint>
//	Strength: basic|medium|advanced
//	DATA: <base64-encoded JSON>
//	Version: <version>
func formatFrontendRecoveryConfig(cfg recoveryConfig, keys []string) string {
	maskedDisplayKeys := make([]string, len(keys))
	for i, k := range keys {
		maskedDisplayKeys[i] = displayMaskKey(k)
	}

	maskedUUID := displayMaskKey(cfg.UUID)
	dataObj := map[string]interface{}{
		"uuid":     maskedUUID,
		"salt":     cfg.Salt,
		"hint_ids": strings.Join(cfg.HintIDs, ","),
		"uuids":    cfg.UUIDs,
	}
	dataJSON, _ := json.Marshal(dataObj)
	dataB64 := base64.StdEncoding.EncodeToString(dataJSON)

	hint := cfg.Hint
	if hint == "" && len(keys) > 0 {
		hint = firstNChars(keys[0], 10)
	}

	var b strings.Builder
	fmt.Fprintln(&b, i18n.T("key_derive.config.derived_keys"))
	for i, mk := range maskedDisplayKeys {
		fmt.Fprintf(&b, "%s%d: %s\n", i18n.T("key_derive.config.key_prefix"), i+1, mk)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, i18n.T("key_derive.config.config_info"))
	fmt.Fprintf(&b, "%s %s\n", i18n.T("key_derive.config.algorithm"), "Argon2id + HKDF")
	fmt.Fprintf(&b, "%s https://tools.wcheer.com/\n", i18n.T("key_derive.config.website"))
	fmt.Fprintf(&b, "%s %s\n", i18n.T("key_derive.config.hint"), hint)
	fmt.Fprintf(&b, "%s %s\n", i18n.T("key_derive.config.strength"), strengthConfigLabel(kdf.Strength(cfg.Strength)))
	fmt.Fprintf(&b, "DATA: %s\n", dataB64)
	fmt.Fprintf(&b, "%s %s\n", i18n.T("key_derive.config.version"), cfg.Version)

	return b.String()
}

// parseFrontendRecoveryConfig parses the frontend text+base64 config format
// back into a recoveryConfig struct. Accepts both English labels (new CLI
// format) and Chinese labels (legacy frontend format) for backward
// compatibility.
func parseFrontendRecoveryConfig(data string) (*recoveryConfig, error) {
	cfg := &recoveryConfig{}
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "Hint: "), strings.HasPrefix(line, i18n.T("key_derive.config.hint")), strings.HasPrefix(line, i18n.T("key_derive.parse.legacy_hint_prefix")):
			prefix := "Hint: "
			if strings.HasPrefix(line, i18n.T("key_derive.config.hint")) {
				prefix = i18n.T("key_derive.config.hint")
			} else if strings.HasPrefix(line, i18n.T("key_derive.parse.legacy_hint_prefix")) {
				prefix = i18n.T("key_derive.parse.legacy_hint_prefix")
			}
			cfg.Hint = strings.TrimSpace(strings.TrimPrefix(line, prefix))
		case strings.HasPrefix(line, "Strength: "), strings.HasPrefix(line, i18n.T("key_derive.config.strength")), strings.HasPrefix(line, i18n.T("key_derive.parse.legacy_strength_prefix")):
			prefix := "Strength: "
			if strings.HasPrefix(line, i18n.T("key_derive.config.strength")) {
				prefix = i18n.T("key_derive.config.strength")
			} else if strings.HasPrefix(line, i18n.T("key_derive.parse.legacy_strength_prefix")) {
				prefix = i18n.T("key_derive.parse.legacy_strength_prefix")
			}
			label := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			cfg.Strength = parseStrengthLabel(label)
		case strings.HasPrefix(line, "Version: "), strings.HasPrefix(line, i18n.T("key_derive.config.version")), strings.HasPrefix(line, i18n.T("key_derive.parse.legacy_version_prefix")):
			prefix := "Version: "
			if strings.HasPrefix(line, i18n.T("key_derive.config.version")) {
				prefix = i18n.T("key_derive.config.version")
			} else if strings.HasPrefix(line, i18n.T("key_derive.parse.legacy_version_prefix")) {
				prefix = i18n.T("key_derive.parse.legacy_version_prefix")
			}
			cfg.Version = strings.TrimSpace(strings.TrimPrefix(line, prefix))
		case strings.HasPrefix(line, "DATA: "):
			b64Data := strings.TrimSpace(strings.TrimPrefix(line, "DATA: "))
			if err := decodeDataJSON(b64Data, cfg); err != nil {
				return nil, err
			}
		}
	}

	// Strength may also come from the old JSON fallback path; for the text
	// format it's extracted above. If absent, default to medium.
	if cfg.Strength == "" {
		cfg.Strength = "medium"
	}

	return cfg, nil
}

// decodeDataJSON decodes the base64 DATA field from the frontend text format
// and populates the relevant recoveryConfig fields.
func decodeDataJSON(b64Data string, cfg *recoveryConfig) error {
	jsonData, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_decode_data"), err)
	}
	var dataObj struct {
		UUID    string   `json:"uuid"`
		Salt    string   `json:"salt"`
		HintIDs string   `json:"hint_ids"`
		UUIDs   []string `json:"uuids"`
	}
	if err := json.Unmarshal(jsonData, &dataObj); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_parse_data_json"), err)
	}
	cfg.UUID = dataObj.UUID
	cfg.Salt = dataObj.Salt
	if dataObj.HintIDs != "" {
		cfg.HintIDs = strings.Split(dataObj.HintIDs, ",")
	} else {
		cfg.HintIDs = []string{}
	}
	cfg.UUIDs = dataObj.UUIDs
	return nil
}

// textFormatRegex detects whether content looks like the frontend text+base64
// config format (as opposed to raw JSON).
var textFormatRegex = regexp.MustCompile(`(?m)^DATA:\s+\S`)

// loadRecoveryConfig reads and parses a recovery config file. It tries the
// frontend text+base64 format first; if that doesn't match, it falls back to
// the legacy raw JSON format for backward compatibility.
func loadRecoveryConfig(path string) (*recoveryConfig, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)

	if textFormatRegex.MatchString(content) {
		cfg, err := parseFrontendRecoveryConfig(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_parse_frontend"), err)
		}
		if cfg.Salt != "" {
			return cfg, nil
		}
	}

	var cfg recoveryConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("key_derive.error.config_parse_json"), err)
	}
	return &cfg, nil
}
