package cmd

import (
	"testing"

	"go-cipher-cli/internal/diceware"
)

func TestParseSeparator(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want diceware.Separator
	}{
		{"hyphen literal", "hyphen", diceware.SepHyphen},
		{"hyphen alias dash", "-", diceware.SepHyphen},
		{"hyphen uppercase", "HYPHEN", diceware.SepHyphen},
		{"hyphen mixed case", "Hyphen", diceware.SepHyphen},
		{"none literal", "none", diceware.SepNone},
		{"none empty", "", diceware.SepNone},
		{"none uppercase", "NONE", diceware.SepNone},
		{"space literal", "space", diceware.SepSpace},
		{"unknown falls back to space", "comma", diceware.SepSpace},
		{"unknown falls back to space 2", "unknown", diceware.SepSpace},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseSeparator(c.in); got != c.want {
				t.Errorf("parseSeparator(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
