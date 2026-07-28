package cmd

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// End-to-end tests for the diceware CLI command.
//
// diceware output is random (CSPRNG-driven), so these tests assert on structure
// (word count, separators, entropy, dice-roll format) rather than exact values,
// mirroring what a user observes on the command line.

// passphraseRe captures the generated passphrase from the "Passphrase:" line.
var passphraseRe = regexp.MustCompile(`(?m)^Passphrase:\s+(.+)$`)

// rollRe matches each per-word detail line, e.g. "  1. [15264] cavity".
var rollRe = regexp.MustCompile(`(?m)^\s*\d+\.\s+\[\d{5}\]\s+\S+$`)

// extractPassphrase pulls the passphrase value out of the CLI output.
func extractPassphrase(t *testing.T, out string) string {
	t.Helper()
	m := passphraseRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no Passphrase line in output:\n%s", out)
	}
	return strings.TrimSpace(m[1])
}

func TestDicewareCmd_Default(t *testing.T) {
	out, code := runCLI(t, "diceware")
	if code != 0 {
		t.Fatalf("diceware failed: %s", out)
	}
	pp := extractPassphrase(t, out)

	// Default is 5 words, no separator.
	if strings.Contains(pp, " ") || strings.Contains(pp, "-") {
		t.Errorf("default (no separator) passphrase should contain no space/hyphen, got %q", pp)
	}
	if !strings.Contains(out, "Words:        5") {
		t.Errorf("expected 5 words, output:\n%s", out)
	}
	// 5 words → ~64.6 bit entropy.
	if !strings.Contains(out, "Entropy:      64.") {
		t.Errorf("expected ~64.x bit entropy for 5 words, output:\n%s", out)
	}
	// 5 detail lines, each "[ddddd] word".
	rolls := rollRe.FindAllString(out, -1)
	if len(rolls) != 5 {
		t.Errorf("expected 5 detail lines, got %d:\n%s", len(rolls), out)
	}
}

func TestDicewareCmd_WordCount(t *testing.T) {
	cases := []struct {
		n       int
		entropy string // expected entropy prefix for n words
	}{
		{4, "51."},
		{6, "77."},
		{8, "103."},
	}
	for _, c := range cases {
		t.Run("n="+strconv.Itoa(c.n), func(t *testing.T) {
			out, code := runCLI(t, "diceware", "-n", strconv.Itoa(c.n))
			if code != 0 {
				t.Fatalf("diceware -n %d failed: %s", c.n, out)
			}
			label := "Words:        " + strconv.Itoa(c.n)
			if !strings.Contains(out, label) {
				t.Errorf("expected %q, output:\n%s", label, out)
			}
			if !strings.Contains(out, "Entropy:      "+c.entropy) {
				t.Errorf("expected entropy prefix %q for %d words, output:\n%s", c.entropy, c.n, out)
			}
			rolls := rollRe.FindAllString(out, -1)
			if len(rolls) != c.n {
				t.Errorf("expected %d detail lines, got %d", c.n, len(rolls))
			}
		})
	}
}

func TestDicewareCmd_Separator(t *testing.T) {
	t.Run("space", func(t *testing.T) {
		out, code := runCLI(t, "diceware", "-n", "3", "--sep", "space")
		if code != 0 {
			t.Fatalf("diceware failed: %s", out)
		}
		pp := extractPassphrase(t, out)
		// 3 words separated by single spaces → exactly 2 spaces.
		if strings.Count(pp, " ") != 2 {
			t.Errorf("space separator: expected 2 spaces in 3-word passphrase, got %q", pp)
		}
		if !strings.Contains(out, "Separator:    space") {
			t.Errorf("expected separator label 'space', output:\n%s", out)
		}
	})

	t.Run("hyphen", func(t *testing.T) {
		out, code := runCLI(t, "diceware", "-n", "3", "--sep", "hyphen")
		if code != 0 {
			t.Fatalf("diceware failed: %s", out)
		}
		pp := extractPassphrase(t, out)
		if strings.Count(pp, "-") != 2 {
			t.Errorf("hyphen separator: expected 2 hyphens in 3-word passphrase, got %q", pp)
		}
		if !strings.Contains(out, "Separator:    hyphen (-)") {
			t.Errorf("expected separator label 'hyphen (-)', output:\n%s", out)
		}
	})

	t.Run("none", func(t *testing.T) {
		out, code := runCLI(t, "diceware", "-n", "3", "--sep", "none")
		if code != 0 {
			t.Fatalf("diceware failed: %s", out)
		}
		pp := extractPassphrase(t, out)
		if strings.ContainsAny(pp, " -") {
			t.Errorf("none separator: passphrase should have no space/hyphen, got %q", pp)
		}
		if !strings.Contains(out, "Separator:    none") {
			t.Errorf("expected separator label 'none', output:\n%s", out)
		}
	})
}

func TestDicewareCmd_Randomness(t *testing.T) {
	// Two consecutive runs must differ (CSPRNG).
	out1, _ := runCLI(t, "diceware")
	pp1 := extractPassphrase(t, out1)
	out2, _ := runCLI(t, "diceware")
	pp2 := extractPassphrase(t, out2)
	if pp1 == pp2 {
		t.Errorf("two diceware runs produced identical passphrase (very unlikely): %q", pp1)
	}
}

func TestDicewareCmd_DiceFormat(t *testing.T) {
	// Every detail line must show a 5-digit dice roll in [1-6]{5}.
	out, code := runCLI(t, "diceware", "-n", "5")
	if code != 0 {
		t.Fatalf("diceware failed: %s", out)
	}
	lines := rollRe.FindAllString(out, -1)
	diceRe := regexp.MustCompile(`\[[1-6]{5}\]`)
	for i, line := range lines {
		if !diceRe.MatchString(line) {
			t.Errorf("detail line %d has invalid dice format: %q", i+1, line)
		}
	}
}
