package diceware

import (
	"math"
	"testing"
)

func TestWordlistIntegrity(t *testing.T) {
	// Must have exactly 7776 words.
	if len(EFFLargeWordlist) != WordlistSize {
		t.Fatalf("expected %d words, got %d", WordlistSize, len(EFFLargeWordlist))
	}

	// First and last words must match EFF official.
	if EFFLargeWordlist[0] != "abacus" {
		t.Errorf("first word: got %q, want abacus", EFFLargeWordlist[0])
	}
	if EFFLargeWordlist[WordlistSize-1] != "zoom" {
		t.Errorf("last word: got %q, want zoom", EFFLargeWordlist[WordlistSize-1])
	}
}

func TestDiceToIndex(t *testing.T) {
	cases := []struct {
		dice string
		word string
	}{
		{"11111", "abacus"},
		{"11112", "abdomen"},
		{"66666", "zoom"},
	}
	for _, c := range cases {
		idx := diceToIndex(c.dice)
		if EFFLargeWordlist[idx] != c.word {
			t.Errorf("dice=%s index=%d: got %q, want %q", c.dice, idx, EFFLargeWordlist[idx], c.word)
		}
	}
}

func TestGeneratePassphrase_WordCount(t *testing.T) {
	for _, n := range []int{2, 4, 5, 8} {
		result, err := GeneratePassphrase(n, SepSpace)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rolls) != n {
			t.Errorf("numWords=%d: got %d rolls", n, len(result.Rolls))
		}
	}
}

func TestGeneratePassphrase_DiceFormat(t *testing.T) {
	result, err := GeneratePassphrase(5, SepSpace)
	if err != nil {
		t.Fatal(err)
	}
	for _, roll := range result.Rolls {
		if len(roll.Dice) != DicePerWord {
			t.Errorf("dice string %q: want %d chars", roll.Dice, DicePerWord)
		}
		for _, ch := range roll.Dice {
			if ch < '1' || ch > '6' {
				t.Errorf("dice string %q: invalid char %c", roll.Dice, ch)
			}
		}
	}
}

func TestGeneratePassphrase_Separators(t *testing.T) {
	t.Run("space", func(t *testing.T) {
		result, _ := GeneratePassphrase(3, SepSpace)
		if result.Passphrase == "" {
			t.Fatal("empty passphrase")
		}
		// Should have 2 spaces between 3 words
		words := splitSep(result.Passphrase, " ")
		if len(words) != 3 {
			t.Errorf("space separator: expected 3 words, got %d", len(words))
		}
	})

	t.Run("hyphen", func(t *testing.T) {
		result, _ := GeneratePassphrase(3, SepHyphen)
		words := splitSep(result.Passphrase, "-")
		if len(words) != 3 {
			t.Errorf("hyphen separator: expected 3 words, got %d", len(words))
		}
	})

	t.Run("none", func(t *testing.T) {
		result, _ := GeneratePassphrase(3, SepNone)
		if contains(result.Passphrase, " ") || contains(result.Passphrase, "-") {
			t.Error("no-separator passphrase should not contain space or hyphen")
		}
	})

	t.Run("passphrase matches rolls", func(t *testing.T) {
		result, _ := GeneratePassphrase(4, SepSpace)
		expected := join(rollWords(result.Rolls), " ")
		if result.Passphrase != expected {
			t.Errorf("passphrase mismatch: got %q, want %q", result.Passphrase, expected)
		}
	})
}

func TestGeneratePassphrase_Entropy(t *testing.T) {
	result, err := GeneratePassphrase(5, SepSpace)
	if err != nil {
		t.Fatal(err)
	}
	expected := EntropyBitsPerWord * 5
	if math.Abs(result.EntropyBits-expected) > 0.001 {
		t.Errorf("entropy: got %f, want %f", result.EntropyBits, expected)
	}
	if result.EntropyBits < 64 || result.EntropyBits > 65 {
		t.Errorf("entropy for 5 words should be ~64.6, got %f", result.EntropyBits)
	}
}

func TestGeneratePassphrase_Combinations(t *testing.T) {
	result, err := GeneratePassphrase(4, SepSpace)
	if err != nil {
		t.Fatal(err)
	}
	expected := math.Pow(WordlistSize, 4)
	if result.Combinations != expected {
		t.Errorf("combinations: got %.0f, want %.0f", result.Combinations, expected)
	}
}

func TestGeneratePassphrase_Randomness(t *testing.T) {
	passphrases := make(map[string]bool)
	for i := 0; i < 50; i++ {
		result, err := GeneratePassphrase(5, SepSpace)
		if err != nil {
			t.Fatal(err)
		}
		passphrases[result.Passphrase] = true
	}
	// 50 iterations of 5-word passphrases: probability of collision is astronomically low.
	if len(passphrases) < 45 {
		t.Errorf("only %d unique passphrases out of 50 — suspiciously low", len(passphrases))
	}
}

func TestGeneratePassphrase_Boundary(t *testing.T) {
	t.Run("zero words clamps to 1", func(t *testing.T) {
		result, _ := GeneratePassphrase(0, SepSpace)
		if len(result.Rolls) != 1 {
			t.Errorf("expected 1 roll, got %d", len(result.Rolls))
		}
	})
	t.Run("negative clamps to 1", func(t *testing.T) {
		result, _ := GeneratePassphrase(-5, SepSpace)
		if len(result.Rolls) != 1 {
			t.Errorf("expected 1 roll, got %d", len(result.Rolls))
		}
	})
	t.Run("huge clamps to 20", func(t *testing.T) {
		result, _ := GeneratePassphrase(100, SepSpace)
		if len(result.Rolls) != 20 {
			t.Errorf("expected 20 rolls, got %d", len(result.Rolls))
		}
	})
}

func TestFormatCombinations(t *testing.T) {
	tests := []struct {
		combinations float64
		contains     string
	}{
		{7776, "7776"},
		{999999, "999999"},
		{math.Pow(7776, 8), "× 10^"},
	}
	for _, tc := range tests {
		s := FormatCombinations(tc.combinations)
		if !contains(s, tc.contains) {
			t.Errorf("FormatCombinations(%.0f) = %q, want substring %q", tc.combinations, s, tc.contains)
		}
	}
}

// helpers

func splitSep(s, sep string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	cur := ""
	for _, r := range s {
		if string(r) == sep {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	out = append(out, cur)
	return out
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func rollWords(rolls []WordRoll) []string {
	words := make([]string, len(rolls))
	for i, r := range rolls {
		words[i] = r.Word
	}
	return words
}
