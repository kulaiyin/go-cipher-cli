package validation

import (
	"strings"
	"testing"
)

func TestCleanText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"spaces stripped", "a b c", "abc"},
		{"newlines stripped", "line1\nline2", "line1line2"},
		{"tabs stripped", "a\tb", "ab"},
		{"mixed whitespace", "  a \n\tb  ", "ab"},
		{"no whitespace", "abc123", "abc123"},
		{"empty", "", ""},
		{"only whitespace", " \n\t ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CleanText(c.in); got != c.want {
				t.Errorf("CleanText(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestValidateKeyDeriveInput(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"20 chars ok", strings.Repeat("a", 20), ""},
		{"more than 20 ok", "this is a recovery seed phrase 07", ""},
		{"19 chars fails", strings.Repeat("a", 19), "key_derive.error.input_too_short"},
		{"empty fails", "", "key_derive.error.input_too_short"},
		{"whitespace not counted", "abcdefghijklmnopqrs", "key_derive.error.input_too_short"},
		{"whitespace stripped counts", "a b c d e f g h i j k l m n o p q r s t u", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateKeyDeriveInput(c.in)
			if c.want == "" {
				if err != nil {
					t.Errorf("ValidateKeyDeriveInput(%q) unexpected error: %v", c.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateKeyDeriveInput(%q) expected error, got nil", c.in)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ValidateKeyDeriveInput(%q) error = %q, want containing %q", c.in, err.Error(), c.want)
			}
		})
	}
}

func TestValidateKeyDerivePassword(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		want string
	}{
		{"valid composite", "D3rive-P@ss", ""},
		{"valid min length", "ab3!cdef", ""},
		{"too short", "ab3!c", "key_derive.error.password_too_short"},
		{"no digit", "abcdefgh!", "key_derive.error.password_weak"},
		{"no letter", "12345678!", "key_derive.error.password_weak"},
		{"no special", "abcd1234", "key_derive.error.password_weak"},
		{"only letters", "abcdefgh", "key_derive.error.password_weak"},
		{"only digits", "12345678", "key_derive.error.password_weak"},
		{"empty", "", "key_derive.error.password_too_short"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateKeyDerivePassword(c.pw)
			if c.want == "" {
				if err != nil {
					t.Errorf("ValidateKeyDerivePassword(%q) unexpected error: %v", c.pw, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateKeyDerivePassword(%q) expected error, got nil", c.pw)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("ValidateKeyDerivePassword(%q) error = %q, want containing %q", c.pw, err.Error(), c.want)
			}
		})
	}
}
