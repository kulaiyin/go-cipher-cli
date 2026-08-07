// Package password ports the web tool's high-strength password generation
// (PasswordGenerationModal.vue + password/fusion.ts) to Go so the CLI produces
// byte-level identical passwords from the same hint answers and salt.
package password

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"go-cipher-cli/internal/crypto"
	"go-cipher-cli/internal/kdf"
)

// defaultSalt matches the web modal's fallback salt; used when no salt is
// provided so the derivation stays consistent across the two implementations.
const defaultSalt = "698fbc35db55bf54e3d645b53b4ebbec8828a82d0afc17ef90694f328eda99c3866ad7daffbde099d5295fe823882f3c1389a07ad326afc56eec9814629f161e"

// specialChars is the punctuation set the fusion step inserts (fusion.ts).
const specialChars = `!@#$%^&*(),.?":{}|<>`

// deterministicCharset is the output alphabet of generateDeterministicString
// (safety-utility.ts), 91 characters ending with a backtick.
const deterministicCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~`"

// NormalizePassword strips every whitespace character and NFC-normalizes the
// result, mirroring fusion.ts normalizePassword. The output is UTF-8 bytes;
// callers may wipe it after the derivation finishes.
func NormalizePassword(password []byte) []byte {
	var sb bytes.Buffer
	sb.Grow(len(password))
	for len(password) > 0 {
		r, size := utf8.DecodeRune(password)
		password = password[size:]
		if !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}
	return norm.NFC.Bytes(sb.Bytes())
}

// safetyMergeStrings interleaves two strings character by character, then
// scatters the remaining characters at positions derived from the running
// length, mirroring fusion.ts safety_merge_strings.
func safetyMergeStrings(strA, strB string) string {
	a := []rune(strA)
	b := []rune(strB)
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	combined := make([]rune, 0, len(a)+len(b))
	for i := 0; i < minLen; i++ {
		combined = append(combined, a[i], b[i])
	}
	remaining := append(a[minLen:], b[minLen:]...)
	L := len(combined)
	for i, ch := range remaining {
		idx := i + 1
		insertPos := 0
		if L > 0 {
			insertPos = (L * idx / 3) % L
		}
		combined = append(combined, 0)
		copy(combined[insertPos+1:], combined[insertPos:])
		combined[insertPos] = ch
		L = len(combined)
	}
	return string(combined)
}

// FusePasswords mixes the salt and the normalized passwords into a single
// string, mirroring fusion.ts fusePasswords.
func FusePasswords(salt string, passwords [][]byte) string {
	lastCharNum := 0
	if len(salt) > 0 {
		lastCharNum = hexDigitVal(rune(salt[len(salt)-1]))
	}
	saltLength := len(salt)
	index := 0
	if saltLength > 0 {
		index = lastCharNum % saltLength
	}
	targetChar := '0'
	if index < len(salt) {
		targetChar = rune(salt[index])
	}
	remainder := base36Val(targetChar) % 3

	segmentLength := (saltLength + 2) / 3
	seg := func(start, end int) string {
		if start >= saltLength {
			return ""
		}
		if end > saltLength {
			end = saltLength
		}
		return salt[start:end]
	}
	segments := []string{
		seg(0, segmentLength),
		seg(segmentLength, segmentLength*2),
		seg(segmentLength*2, segmentLength*3),
	}

	combined := ""
	for segIdx := 0; segIdx < 3; segIdx++ {
		idx := (remainder + segIdx + 1) % 3
		combined += safetyMergeStrings(segments[segIdx], string(passwords[idx]))
	}

	temp := []rune(combined)
	result := ""
	switch remainder {
	case 0:
		for len(temp) > 0 {
			result += string(temp[0])
			temp = temp[1:]
			if len(temp) > 0 {
				result += string(temp[len(temp)-1])
				temp = temp[:len(temp)-1]
			}
		}
	case 1:
		for i := 0; i < len(temp); i += 2 {
			result += string(temp[i])
		}
		for i := 1; i < len(temp); i += 2 {
			result += string(temp[i])
		}
	case 2:
		third := len(temp) / 3
		if third > 0 {
			part2 := []rune(string(temp[third : 2*third]))
			for i, j := 0, len(part2)-1; i < j; i, j = i+1, j-1 {
				part2[i], part2[j] = part2[j], part2[i]
			}
			result = string(temp[:third]) + string(part2) + string(temp[2*third:])
		} else {
			result = combined
		}
	default:
		result = combined
	}

	saltLastByte := 0
	switch {
	case len(salt) >= 2:
		saltLastByte = hexPairVal(salt[len(salt)-2:])
	case len(salt) == 1:
		saltLastByte = hexDigitVal(rune(salt[0]))
	}
	specialCharCount := (saltLastByte % 3) + 1
	saltHash := 0
	for i := 0; i < len(salt); i++ {
		saltHash += int(salt[i])
	}

	finalResult := []rune(result)
	for i := 0; i < specialCharCount; i++ {
		positionIndex := (saltHash + i*13) % (len(finalResult) + 1)
		charIndex := (saltHash + i*7) % len(specialChars)
		finalResult = append(finalResult, 0)
		copy(finalResult[positionIndex+1:], finalResult[positionIndex:])
		finalResult[positionIndex] = rune(specialChars[charIndex])
	}
	return string(finalResult)
}

// DeriveNewSalt derives the fusion salt from the original salt, mirroring the
// web modal's watch on props.salt: argon2id(originalSalt, salt=originalSalt+
// ":"+defaultSalt, 32MiB, t=3, p=1, dkLen=64) returned as a hex string.
func DeriveNewSalt(originalSalt string) (string, error) {
	if originalSalt == "" {
		originalSalt = defaultSalt
	}
	res := kdf.Argon2([]byte(originalSalt), kdf.Argon2Config{
		Salt:        []byte(originalSalt + ":" + defaultSalt),
		MemorySize:  32 * 1024,
		Iterations:  3,
		Parallelism: 1,
		HashLength:  64,
	})
	if !res.Success {
		return "", errors.New(res.Error)
	}
	return hex.EncodeToString(res.Data), nil
}

// ComputeFinalPassword produces the web's high-strength password from the
// original salt and the three step passwords: normalize, fuse with the derived
// salt, HMAC-SHA3-512 keyed by the derived salt, then render a 128-char
// deterministic string from the ASCII bytes of the HMAC hex digest.
// The passwords are UTF-8 bytes; the derived password is returned as a string.
func ComputeFinalPassword(salt string, passwords [][]byte) (string, error) {
	newSalt, err := DeriveNewSalt(salt)
	if err != nil {
		return "", err
	}
	normalized := make([][]byte, len(passwords))
	for i, p := range passwords {
		normalized[i] = NormalizePassword(p)
	}
	fused := FusePasswords(newSalt, normalized)
	hmacRes := crypto.HMAC(fused, "hmac-sha3-512", newSalt)
	if !hmacRes.Success {
		return "", errors.New(hmacRes.Error)
	}
	return generateDeterministicString([]byte(hmacRes.Data), 128), nil
}

// generateDeterministicString derives a fixed-length string from input bytes
// via HKDF-SHA3-512 rejection sampling, mirroring safety-utility.ts
// generate_deterministic_string.
func generateDeterministicString(input []byte, length int) string {
	charsetLen := len(deterministicCharset)
	maxValidByte := 255 - (256 % charsetLen)
	if length < 1 {
		length = 1
	}
	result := make([]byte, length)
	counter := 0
	filled := 0
	for filled < length {
		info := []byte(fmt.Sprintf("determin-string-%d", counter))
		counter++
		derived := kdf.HKDF(input, nil, info, 128)
		for _, b := range derived {
			if filled >= length {
				break
			}
			if int(b) <= maxValidByte {
				result[filled] = deterministicCharset[int(b)%charsetLen]
				filled++
			}
		}
	}
	return string(result)
}

func hexDigitVal(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'a' && r <= 'f':
		return int(r-'a') + 10
	case r >= 'A' && r <= 'F':
		return int(r-'A') + 10
	}
	return 0
}

func hexPairVal(s string) int {
	if len(s) < 2 {
		return 0
	}
	r, _ := utf8.DecodeRuneInString(s)
	return hexDigitVal(r)*16 + hexDigitVal(rune(s[1]))
}

func base36Val(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'a' && r <= 'z':
		return int(r-'a') + 10
	case r >= 'A' && r <= 'Z':
		return int(r-'A') + 10
	}
	return 0
}
