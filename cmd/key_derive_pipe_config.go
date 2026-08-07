package cmd

// bytes-typed recovery config rendering for key-derive-pipe: the pipe layer
// holds the derived keys as raw wipeable bytes, so the config text is built
// into a wipeable []byte without ever materializing a full key hex string.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

// buildPipeRecoveryConfig constructs the config from a raw-bytes derivation
// result. UUIDs carries the masked (first8 + last8) form of each derived key
// plus the UUID, matching buildRecoveryConfig / the frontend download format.
// The config carries only fingerprints, never full keys, and the full UUID hex
// is never materialized (the masked form is rendered from raw bytes).
func buildPipeRecoveryConfig(r kdf.KeySetBytesResult, hint string, hintIDs []string) recoveryConfig {
	uuids := make([]string, 0, len(r.RawKeys)+1)
	for _, k := range r.RawKeys {
		uuids = append(uuids, maskedKeyBytes(k))
	}
	uuids = append(uuids, maskedKeyBytes(r.RawUUID))
	return recoveryConfig{
		Version:  keyDeriveKeyDriveVersion,
		Strength: string(r.Strength),
		Salt:     r.SaltSeed,
		Hint:     hint,
		HintIDs:  hintIDs,
		UUIDs:    uuids,
	}
}

// maskedKeyBytes returns the first-8/last-8 hex fingerprint of raw key bytes,
// the exact format ValidateKeyRecoveryBytes checks against.
func maskedKeyBytes(raw []byte) string {
	prefix := 4
	if prefix > len(raw) {
		prefix = len(raw)
	}
	suffixStart := len(raw) - 4
	if suffixStart < 0 {
		suffixStart = 0
	}
	var b []byte
	b = appendKeyHexBytes(b, raw[:prefix])
	b = appendKeyHexBytes(b, raw[suffixStart:])
	return string(b)
}

// displayMaskKeyBytes matches displayMaskKey on the hex encoding of raw:
// first 8 hex chars + asterisks + last 8 hex chars.
func displayMaskKeyBytes(raw []byte) []byte {
	hexLen := hex.EncodedLen(len(raw))
	if hexLen <= 16 {
		return appendKeyHexBytes(nil, raw)
	}
	out := make([]byte, 0, hexLen)
	out = appendKeyHexBytes(out, raw[:4])
	out = append(out, strings.Repeat("*", hexLen-16)...)
	out = appendKeyHexBytes(out, raw[len(raw)-4:])
	return out
}

// appendKeyHexBytes appends the lowercase hex encoding of src to dst.
func appendKeyHexBytes(dst, src []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, hex.EncodedLen(len(src)))...)
	hex.Encode(dst[start:], src)
	return dst
}

// formatFrontendRecoveryConfigBytes renders the recovery config in the same
// multilingual text+base64 format as formatFrontendRecoveryConfig, but builds
// the text into a wipeable []byte from raw key bytes (rawUUID) so no full key
// hex string lingers.
func formatFrontendRecoveryConfigBytes(cfg recoveryConfig, rawKeys [][]byte, rawUUID []byte) []byte {
	maskedKeys := make([][]byte, len(rawKeys))
	for i, k := range rawKeys {
		maskedKeys[i] = displayMaskKeyBytes(k)
	}
	maskedUUID := displayMaskKeyBytes(rawUUID)

	dataObj := map[string]interface{}{
		"uuid":     string(maskedUUID),
		"salt":     cfg.Salt,
		"hint_ids": strings.Join(cfg.HintIDs, ","),
		"uuids":    cfg.UUIDs,
	}
	dataJSON, _ := json.Marshal(dataObj)
	dataB64 := base64.StdEncoding.EncodeToString(dataJSON)

	hint := cfg.Hint
	if hint == "" && len(rawKeys) > 0 {
		n := 5
		if n > len(rawKeys[0]) {
			n = len(rawKeys[0])
		}
		hint = hex.EncodeToString(rawKeys[0][:n])
	}

	var b []byte
	b = append(b, i18n.T("key_derive.config.derived_keys")...)
	b = append(b, '\n')
	for i, mk := range maskedKeys {
		b = append(b, i18n.T("key_derive.config.key_prefix")...)
		b = strconv.AppendInt(b, int64(i+1), 10)
		b = append(b, ':', ' ')
		b = append(b, mk...)
		b = append(b, '\n')
	}
	b = append(b, '\n')
	b = append(b, i18n.T("key_derive.config.config_info")...)
	b = append(b, '\n')
	b = append(b, i18n.T("key_derive.config.algorithm")...)
	b = append(b, " Argon2id + HKDF\n"...)
	b = append(b, i18n.T("key_derive.config.website")...)
	b = append(b, " https://tools.wcheer.com/\n"...)
	b = append(b, i18n.T("key_derive.config.hint")...)
	b = append(b, ' ')
	b = append(b, hint...)
	b = append(b, '\n')
	b = append(b, i18n.T("key_derive.config.strength")...)
	b = append(b, ' ')
	b = append(b, strengthConfigLabel(kdf.Strength(cfg.Strength))...)
	b = append(b, '\n')
	b = append(b, "DATA: "...)
	b = append(b, dataB64...)
	b = append(b, '\n')
	b = append(b, i18n.T("key_derive.config.version")...)
	b = append(b, ' ')
	b = append(b, cfg.Version...)
	b = append(b, '\n')

	return b
}
