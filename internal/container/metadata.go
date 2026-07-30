package container

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/safety"
)

// MetaData mirrors the web tool's meta-data.json structure
// (DataEncryptionForm.vue MetaData interface). metaHash and integrityHash are
// the two HMAC-SHA3-512 signatures computed by SignMetaData.
type MetaData struct {
	Version       uint32   `json:"version"`
	Salt          string   `json:"salt"`
	CreatedAt     int64    `json:"createdAt"`
	Hint          string   `json:"hint"`
	SelectedHints []string `json:"selectedHints"`
	FileName      string   `json:"fileName,omitempty"`
	FileType      string   `json:"fileType,omitempty"`
	SHA256        string   `json:"sha256"`
	MetaHash      string   `json:"metaHash,omitempty"`
	IntegrityHash string   `json:"integrityHash,omitempty"`
}

// metaPayload builds the deterministic signing payload, matching the web tool's
// calculate_meta_data_digest exactly:
//
//	payload = [version, salt, sorted(selectedHints).join(","), sha256, createdAt].join("|")
//
// version and createdAt are formatted as plain decimal integers (JS implicit
// String() on integer-valued numbers), selectedHints are sorted ascending.
func (m *MetaData) metaPayload() string {
	sortedHints := append([]string{}, m.SelectedHints...)
	sort.Strings(sortedHints)
	parts := []string{
		strconv.FormatUint(uint64(m.Version), 10),
		m.Salt,
		strings.Join(sortedHints, ","),
		m.SHA256,
		strconv.FormatInt(m.CreatedAt, 10),
	}
	return strings.Join(parts, "|")
}

// SignMetaData computes and fills MetaHash and IntegrityHash in place.
//
//   - MetaHash:      HMAC-SHA3-512(payload, key = salt hex-string bytes)
//     Weak import-time check; verifies without knowing the passwords.
//   - IntegrityHash: HMAC-SHA3-512(payload, key = assemblePackageKey raw bytes)
//     Strong decrypt-time check; requires the correct first three strong keys.
//
// assemblePackageKey may be nil to compute only MetaHash (used during import
// validation before the user supplies keys).
func (m *MetaData) SignMetaData(assemblePackageKey []byte) {
	payload := m.metaPayload()
	// metaHash key = UTF-8 bytes of the salt hex string (key=salt as a string).
	m.MetaHash = safety.HMACSHA3512([]byte(payload), []byte(m.Salt))
	if len(assemblePackageKey) > 0 {
		m.IntegrityHash = safety.HMACSHA3512([]byte(payload), assemblePackageKey)
	}
}

// VerifyMetaHash recomputes MetaHash (key=salt) and reports whether it matches
// the stored value. Used for the import-time weak integrity check.
func (m *MetaData) VerifyMetaHash() bool {
	if m.MetaHash == "" {
		return false
	}
	payload := m.metaPayload()
	return safety.HMACSHA3512([]byte(payload), []byte(m.Salt)) == m.MetaHash
}

// VerifyIntegrityHash recomputes IntegrityHash (key=assemblePackageKey) and
// reports whether it matches the stored value. Used for the decrypt-time strong
// check. Returns false when no stored hash exists.
func (m *MetaData) VerifyIntegrityHash(assemblePackageKey []byte) bool {
	if m.IntegrityHash == "" || len(assemblePackageKey) == 0 {
		return false
	}
	payload := m.metaPayload()
	return safety.HMACSHA3512([]byte(payload), assemblePackageKey) == m.IntegrityHash
}

// ValidateMetaDataFields checks the required meta-data fields per the web tool's
// validateAndParseBundle rules: hint must be a string and sha256 must be present;
// selectedHints must be an array. createdAt defaults to 0 when missing.
func (m *MetaData) ValidateMetaDataFields() error {
	if strings.TrimSpace(m.SHA256) == "" {
		return fmt.Errorf("%s", i18n.T("metadata.error.incomplete"))
	}
	if m.SelectedHints == nil {
		return fmt.Errorf("%s", i18n.T("metadata.error.hints_format"))
	}
	return nil
}

// ParseMetaData decodes meta-data.json bytes into a MetaData.
func ParseMetaData(raw []byte) (*MetaData, error) {
	var md MetaData
	if err := json.Unmarshal(raw, &md); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("metadata.error.parse_failed"), err)
	}
	// createdAt defaults to 0 when absent (matches web: metaData.createdAt ||= 0).
	return &md, nil
}

// MarshalMetaData serializes a MetaData to pretty JSON (2-space indent), matching
// the web tool's JSON.stringify(meta_data, null, 2).
func MarshalMetaData(m *MetaData) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
