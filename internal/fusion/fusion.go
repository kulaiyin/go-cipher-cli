// Package fusion implements password aggregation: a pure, deterministic string
// transformation with no cryptographic primitives. Behaviour is locked by golden
// vectors in internal/testvectors.
package fusion

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"

	"go-cipher-cli/internal/safety"
)

// NormalizePassword removes all whitespace and applies Unicode NFC normalization.
func NormalizePassword(password string) string {
	noSpaces := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' {
			return -1
		}
		return r
	}, password)
	// also strip any remaining unicode-space runes
	noSpaces = strings.Map(func(r rune) rune {
		if isUnicodeSpace(r) {
			return -1
		}
		return r
	}, noSpaces)
	return norm.NFC.String(noSpaces)
}

// isUnicodeSpace reports whether r is a unicode whitespace rune.
func isUnicodeSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		0x00A0, 0x1680,
		0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
		0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
		0xFEFF:
		return true
	}
	return false
}

// safetyMergeStrings interleaves the common-length prefix, then splices the
// remaining tail characters at positions floor(L*index/3) % L, where L grows
// after each insertion.
func safetyMergeStrings(strA, strB string) string {
	ra := []rune(strA)
	rb := []rune(strB)
	minLen := len(ra)
	if len(rb) < minLen {
		minLen = len(rb)
	}

	combined := []rune{}
	for i := 0; i < minLen; i++ {
		combined = append(combined, ra[i], rb[i])
	}

	remaining := append(append([]rune{}, ra[minLen:]...), rb[minLen:]...)

	for i, ch := range remaining {
		index := i + 1 // iterate from 1
		L := len(combined)
		insertPos := (int(math.Floor(float64(L*index)/3.0)) % L)
		// splice at insertPos
		combined = append(combined[:insertPos], append([]rune{ch}, combined[insertPos:]...)...)
	}

	return string(combined)
}

// FusePasswords fuses normalized passwords with the salt into a strengthened string.
// salt is the derived salt string; passwords must already be normalized (length-3 design).
func FusePasswords(salt string, passwords []string) string {
	saltRunes := []rune(salt)
	saltLength := len(saltRunes)

	// Step 1: last char -> number (base 16).
	lastChar := byte('0')
	if saltLength > 0 {
		lastChar = byte(saltRunes[saltLength-1])
	}
	lastCharNum := parseIntBase16OrDefault(string(lastChar), 0)

	// Step 2: salt[ index % saltLength ].
	index := lastCharNum % saltLength
	targetChar := byte('0')
	if saltLength > 0 {
		targetChar = byte(saltRunes[index])
	}

	// Step 3: base36 % 3.
	targetNum := parseIntBase36OrDefault(string(targetChar), 0)
	remainder := targetNum % 3

	// Step 4: split salt into 3 segments.
	segmentLength := int(math.Ceil(float64(saltLength) / 3.0))
	seg1 := string(saltRunes[:segmentLength])
	var seg2 string
	if segmentLength*2 <= saltLength {
		seg2 = string(saltRunes[segmentLength : segmentLength*2])
	} else {
		seg2 = string(saltRunes[segmentLength:])
	}
	var seg3 string
	if segmentLength*2 <= saltLength {
		seg3 = string(saltRunes[segmentLength*2:])
	} else {
		seg3 = ""
	}
	saltSegments := []string{seg1, seg2, seg3}

	// Step 5: combine per (remainder+seg_index+1)%3.
	combined := ""
	for segIndex := 0; segIndex < 3; segIndex++ {
		pwIdx := (remainder + segIndex + 1) % 3
		pw := ""
		if pwIdx < len(passwords) {
			pw = passwords[pwIdx]
		}
		combined += safetyMergeStrings(saltSegments[segIndex], pw)
	}

	// Step 6: shuffle by remainder.
	temp := []rune(combined)
	result := []rune{}
	switch remainder {
	case 0:
		// alternate left then right
		for len(temp) > 0 {
			result = append(result, temp[0])
			temp = temp[1:]
			if len(temp) > 0 {
				result = append(result, temp[len(temp)-1])
				temp = temp[:len(temp)-1]
			}
		}
	case 1:
		// even indices first, then odd
		for i := 0; i < len(temp); i += 2 {
			result = append(result, temp[i])
		}
		for i := 1; i < len(temp); i += 2 {
			result = append(result, temp[i])
		}
	case 2:
		// reverse middle third
		third := len(temp) / 3
		if third > 0 {
			part1 := temp[:third]
			part2 := append([]rune{}, temp[third:2*third]...)
			// reverse part2
			for i, j := 0, len(part2)-1; i < j; i, j = i+1, j-1 {
				part2[i], part2[j] = part2[j], part2[i]
			}
			part3 := temp[2*third:]
			result = append(append(append([]rune{}, part1...), part2...), part3...)
		} else {
			result = append(result, temp...)
		}
	default:
		result = append(result, temp...)
	}

	// Step 7: insert 1-3 special chars derived from salt.
	specialChars := "!@#$%^&*(),.?\":{}|<>"
	specialRunes := []rune(specialChars)

	last2 := ""
	if saltLength >= 2 {
		last2 = string(saltRunes[saltLength-2:])
	} else if saltLength == 1 {
		last2 = string(saltRunes)
	}
	saltLastByte := parseIntBase16OrDefault(last2, 0)
	specialCharCount := (saltLastByte % 3) + 1

	// saltHash = sum of charCodeAt over salt runes.
	saltHash := 0
	for _, r := range saltRunes {
		saltHash += int(r)
	}

	finalResult := append([]rune{}, result...)
	for i := 0; i < specialCharCount; i++ {
		positionIndex := (saltHash + i*13) % (len(finalResult) + 1)
		charIndex := (saltHash + i*7) % len(specialRunes)
		specialChar := specialRunes[charIndex]
		finalResult = append(finalResult[:positionIndex], append([]rune{specialChar}, finalResult[positionIndex:]...)...)
	}

	return string(finalResult)
}

// ComputeFinalPassword normalizes all passwords then fuses them.
// (deriveNewSalt is intentionally omitted — callers pass the already-derived salt.)
func ComputeFinalPassword(salt string, passwords []string) string {
	normalized := make([]string, len(passwords))
	for i, p := range passwords {
		normalized[i] = NormalizePassword(p)
	}
	return FusePasswords(salt, normalized)
}

// DeriveNewSalt derives a new 8-byte (16-hex) salt from the original salt using argon2id
// with the salt string used as both password and salt (i.e. the salt's ASCII bytes — NOT
// hex-decoded), t=3, m=65536 KiB (64 MiB), p=4, dkLen=8. On failure it returns the original
// salt and the error; callers may ignore the error.
func DeriveNewSalt(originalSalt string) (string, error) {
	saltBytes := []byte(originalSalt) // ASCII bytes of the salt string
	out, err := safety.Argon2id([]byte(originalSalt), saltBytes, 3, 64*1024, 4, 8)
	if err != nil {
		return originalSalt, err
	}
	return hex.EncodeToString(out), nil
}

func parseIntBase16OrDefault(s string, def int) int {
	n, err := strconv.ParseInt(s, 16, 64)
	if err != nil {
		return def
	}
	return int(n)
}

func parseIntBase36OrDefault(s string, def int) int {
	n, err := strconv.ParseInt(s, 36, 64)
	if err != nil {
		return def
	}
	return int(n)
}
