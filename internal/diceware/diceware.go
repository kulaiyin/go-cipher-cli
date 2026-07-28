// Package diceware implements the Diceware passphrase generator using the
// EFF large wordlist (7776 words), matching the frontend's
// generateDicewarePassphrase in password/diceware.ts byte-for-byte.
//
// Security: randomness comes from crypto/rand (Go's CSPRNG).
package diceware

import (
	"crypto/rand"
	"fmt"
	"math"
)

const (
	// DicePerWord is the number of dice rolls per word (EFF large wordlist uses 5).
	DicePerWord = 5

	// WordlistSize is the total number of words = 6^5 = 7776.
	WordlistSize = 7776

)

// EntropyBitsPerWord is log2(7776) ≈ 12.9248.
var EntropyBitsPerWord = math.Log2(WordlistSize)

// Separator type for joining words.
type Separator string

const (
	SepSpace  Separator = "space"
	SepHyphen Separator = "hyphen"
	SepNone   Separator = "none"
)

// sepChar maps Separator to its actual join character.
var sepChar = map[Separator]string{
	SepSpace:  " ",
	SepHyphen: "-",
	SepNone:   "",
}

// WordRoll records the dice string and resulting word for one position.
type WordRoll struct {
	Dice string // 5-digit dice string, e.g. "42531"
	Word string
}

// DicewareResult holds the full generation output.
type DicewareResult struct {
	Rolls        []WordRoll
	Passphrase   string
	EntropyBits  float64
	Combinations float64 // 7776^n exceeds int64 for n >= 8
}

// rollDie returns a cryptographically secure random integer in [1, 6] using
// rejection sampling to eliminate modulo bias. Uses crypto/rand (Go's CSPRNG)
// matching the frontend's crypto.getRandomValues.
func rollDie() (int, error) {
	buf := make([]byte, 1)
	// 256 is not divisible by 6, so reject 252..255 to avoid bias.
	const maxValid = 256 - (256 % 6) // 252

	for {
		if _, err := rand.Read(buf); err != nil {
			return 0, fmt.Errorf("rand: %w", err)
		}
		if buf[0] < maxValid {
			return int(buf[0]%6) + 1, nil
		}
	}
}

// rollWordDice generates a 5-digit dice string like "42531".
func rollWordDice() (string, error) {
	dice := make([]byte, DicePerWord)
	for i := 0; i < DicePerWord; i++ {
		d, err := rollDie()
		if err != nil {
			return "", err
		}
		dice[i] = byte('0' + d)
	}
	return string(dice), nil
}

// diceToIndex converts a 5-char dice string (each char '1'..'6') to a
// 0-based index into the EFF wordlist using base-6 encoding:
//
//	index = Σ (dice[i] - '1') * 6^(4-i)  for i=0..4
func diceToIndex(dice string) int {
	idx := 0
	for i := 0; i < len(dice); i++ {
		idx = idx*6 + int(dice[i]-'1')
	}
	return idx
}

// GeneratePassphrase generates a Diceware passphrase.
//
//	numWords: number of words (2-8 recommended, clamped to 1-20)
//	separator: how to join the words (space, hyphen, or none)
func GeneratePassphrase(numWords int, separator Separator) (DicewareResult, error) {
	if numWords < 1 {
		numWords = 1
	}
	if numWords > 20 {
		numWords = 20
	}

	rolls := make([]WordRoll, 0, numWords)
	words := make([]string, 0, numWords)

	for i := 0; i < numWords; i++ {
		dice, err := rollWordDice()
		if err != nil {
			return DicewareResult{}, err
		}
		idx := diceToIndex(dice)
		word := EFFLargeWordlist[idx]
		rolls = append(rolls, WordRoll{Dice: dice, Word: word})
		words = append(words, word)
	}

	s, ok := sepChar[separator]
	if !ok {
		s = " "
	}
	passphrase := join(words, s)

	return DicewareResult{
		Rolls:        rolls,
		Passphrase:   passphrase,
		EntropyBits:  EntropyBitsPerWord * float64(numWords),
		Combinations: math.Pow(float64(WordlistSize), float64(numWords)),
	}, nil
}

// join is a simple strings.Join wrapper.
func join(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	out := elems[0]
	for _, e := range elems[1:] {
		out += sep + e
	}
	return out
}

// FormatCombinations formats a combination count into a human-readable string.
//
// < 1e6 → integer (e.g. "7776")
// >= 1e6 → scientific notation (e.g. "1.61 × 10^31")
// non-finite → "∞"
func FormatCombinations(combinations float64) string {
	if combinations < 1e6 {
		return fmt.Sprintf("%.0f", combinations)
	}
	if !math.IsInf(combinations, 0) {
		exp := math.Floor(math.Log10(combinations))
		mantissa := combinations / math.Pow(10, exp)
		return fmt.Sprintf("%.2f × 10^%d", mantissa, int(exp))
	}
	return "∞"
}
