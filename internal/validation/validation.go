package validation

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/text/unicode/norm"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/safety"
)

// whitespaceRe matches any run of whitespace (including newlines), matching the
// frontend's /[\s\n]+/g used to clean input/password.
var whitespaceRe = regexp.MustCompile(`[\s\n]+`)

// CleanText strips all whitespace/newlines and NFC-normalizes, matching the
// frontend (KeyDerivationForm.vue:680-681).
func CleanText(s string) string {
	cleaned := whitespaceRe.ReplaceAllString(s, "")
	return norm.NFC.String(cleaned)
}

// ValidateKeyDeriveInput checks that input is at least 20 non-space chars
// after cleaning (frontend: KeyDerivationForm.vue:640-641).
func ValidateKeyDeriveInput(s string) error {
	cleaned := CleanText(s)
	if len([]rune(cleaned)) < 20 {
		return fmt.Errorf("%s", i18n.TWithData("key_derive.error.input_too_short", map[string]interface{}{
			"Len": len([]rune(cleaned)),
		}))
	}
	return nil
}

// ValidateKeyDerivePassword checks password rules matching the frontend
// (KeyDerivationForm.vue:430-432, regexp.ts:67-71): at least 8 chars after
// trimming, must contain letter, digit, and special character (or high
// strength). Delegates to safety.IsPassword1Valid for consistency with the
// data_cipher command, so both commands use the same rule set.
func ValidateKeyDerivePassword(pw string) error {
	pw = strings.TrimSpace(pw)

	if len([]rune(pw)) < 8 {
		return fmt.Errorf("%s", i18n.T("key_derive.error.password_too_short"))
	}
	if !safety.IsPassword1Valid(pw) {
		return fmt.Errorf("%s", i18n.T("key_derive.error.password_weak"))
	}
	return nil
}
