// Package aesgcm implements the AES-256-GCM key-derivation and encryption core.
//
// Key derivation pipeline (GenerateAesGcmKey):
//  1. salt_text   = SHA256(pw) for each pw, sorted, joined by ":"
//  2. salt_prk    = HMAC-SHA3-512(key=salt, msg=salt_text)   (hex string)
//  3. s1..sdata   = HKDF(salt_prk, info=<label>, L=64)        (4 sub-keys)
//  4. each weak pw -> argon2id(pw, salt=s1, t=3,m=32768,p=2,dkLen=64) -> hex
//     then base64Decode(hashHex) -> hex again
//  5. usr_strong  = processedPws.sort().join(":")
//  6. prk_dek     = HMAC-SHA3-512(key=s3, msg=usr_strong)     (hex string)
//  7. aes_dek     = HKDF(prk_dek, info="aes-256-gcm-final-key", L=32)
//
// returns (aes_dek, sdata) as 32- and 64-byte keys.
//
// GCM encryption (GcmEncrypt):
//
//	iv(12 random) is stored in the clear; the actual GCM nonce is
//	iv_used = HKDF(HMAC-SHA3-512(key=salt,msg=iv), info="aes-gcm-iv", L=12).
package aesgcm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/safety"
)

// labels for HKDF info fields.
var (
	infoArgon2Salt     = []byte("argon2id-salt")
	infoHkdfSafetyKey  = []byte("hkdf-safety-key")
	infoAesGcmDek      = []byte("aes-256-gcm-dek")
	infoAesGcmData     = []byte("aes-256-gcm-data")
	infoAesGcmFinalKey = []byte("aes-256-gcm-final-key")
	infoAesGcmIV       = []byte("aes-gcm-iv")
)

// reStrongPasswordHex matches the "already strong" passthrough (128 hex chars).
var reStrongPasswordHex = regexp.MustCompile(`^[0-9a-fA-F]{128}$`)

// GenerateAesGcmKey derives the AES-256 DEK and the data salt (sdata) from a
// salt_seed hex string and a password list. The passwords are UTF-8 bytes;
// callers wipe them after the derivation finishes.
func GenerateAesGcmKey(salt string, passwords [][]byte) (key, saltOut []byte, err error) {
	valid := getValidPasswords(passwords)
	saltText := passwordsToSaltText(valid)
	saltPrk := safety.HMACSHA3512([]byte(saltText), []byte(salt)) // key=salt(hex string ASCII)
	s1 := safety.HKDFExpand(saltPrk, infoArgon2Salt, 64)
	s3 := safety.HKDFExpand(saltPrk, infoAesGcmDek, 64)
	sdata := safety.HKDFExpand(saltPrk, infoAesGcmData, 64)

	processed, err := processPasswords(valid, s1)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(processed, func(i, j int) bool { return bytes.Compare(processed[i], processed[j]) < 0 })
	usrStrongKey := bytes.Join(processed, []byte(":"))
	prkDek := safety.HMACSHA3512(usrStrongKey, s3) // key=s3 bytes
	aesDek := safety.HKDFExpand(prkDek, infoAesGcmFinalKey, 32)
	return aesDek, sdata, nil
}

// EncryptWithPassword derives the key from salt+passwords and AES-256-GCM encrypts data.
func EncryptWithPassword(data []byte, salt string, passwords [][]byte) ([]byte, error) {
	if len(data) == 0 || len(passwords) == 0 {
		return nil, errors.New(i18n.T("aesgcm.error.invalid_input"))
	}
	key, saltOut, err := GenerateAesGcmKey(salt, passwords)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	defer wipe(saltOut)
	return GcmEncrypt(data, key, saltOut)
}

// DecryptWithPassword derives the key from salt+passwords and AES-256-GCM decrypts enc.
func DecryptWithPassword(enc []byte, salt string, passwords [][]byte) ([]byte, error) {
	if len(enc) == 0 || len(passwords) == 0 {
		return nil, errors.New(i18n.T("aesgcm.error.empty_data"))
	}
	key, saltOut, err := GenerateAesGcmKey(salt, passwords)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	defer wipe(saltOut)
	dec, err := GcmDecrypt(enc, key, saltOut)
	if err != nil {
		return nil, errors.New(i18n.T("aesgcm.error.wrong_password"))
	}
	return dec, nil
}

// GcmEncrypt encrypts data with a random 12-byte IV.
func GcmEncrypt(data, key, salt []byte) ([]byte, error) {
	iv := safety.GenerateRandomBytes(12)
	return gcmEncryptWithIV(data, key, salt, iv)
}

// gcmEncryptWithIV encrypts data with a caller-supplied IV (used for
// deterministic tests).
func gcmEncryptWithIV(data, key, salt, iv []byte) ([]byte, error) {
	dataPrk := safety.HMACSHA3512(iv, salt)
	ivUsed := safety.HKDFExpand(dataPrk, infoAesGcmIV, 12)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: %w", err)
	}
	ct := gcm.Seal(nil, ivUsed, data, nil)
	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// GcmDecrypt decrypts enc (12-byte IV prefix) with AES-256-GCM.
func GcmDecrypt(enc, key, salt []byte) ([]byte, error) {
	if len(enc) < 12 {
		return nil, fmt.Errorf("aesgcm: ciphertext too short")
	}
	iv := enc[:12]
	ct := enc[12:]
	dataPrk := safety.HMACSHA3512(iv, salt)
	ivUsed := safety.HKDFExpand(dataPrk, infoAesGcmIV, 12)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: %w", err)
	}
	pt, err := gcm.Open(nil, ivUsed, ct, nil)
	if err != nil {
		return nil, err // GCM auth failure
	}
	return pt, nil
}

// getValidPasswords drops empty-after-trim entries.
func getValidPasswords(passwords [][]byte) [][]byte {
	out := make([][]byte, 0, len(passwords))
	for _, p := range passwords {
		if len(bytes.TrimSpace(p)) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// passwordsToSaltText builds the salt text: SHA256 of each pw, sorted and joined by ":".
func passwordsToSaltText(passwords [][]byte) string {
	hashed := make([]string, len(passwords))
	for i, p := range passwords {
		hashed[i] = safety.SHA256Hex(string(p))
	}
	sort.Strings(hashed)
	return strings.Join(hashed, ":")
}

// processPasswords strengthens weak passwords via argon2id; strong (128-hex)
// passwords pass through lowercased.
func processPasswords(passwords [][]byte, s1 []byte) ([][]byte, error) {
	out := make([][]byte, 0, len(passwords))
	for _, p := range passwords {
		ps := string(p)
		strength := checkPasswordStrength(ps)
		if strength < 8 || !reStrongPasswordHex.MatchString(ps) {
			res := kdf.Argon2(p, kdf.Argon2Config{
				Salt:        s1,
				Iterations:  3,
				MemorySize:  32 * 1024, // 32 MiB
				Parallelism: 2,
				HashLength:  64,
			})
			if !res.Success {
				return nil, fmt.Errorf("aesgcm: strengthen: %s", res.Error)
			}
			// Decode the argon2 hex digest as if it were base64, then hex-encode the result.
			quirked, err := base64.StdEncoding.DecodeString(res.Data)
			if err != nil {
				// Fall back to the raw bytes of the hex string if base64 decoding fails.
				quirked = []byte(res.Data)
			}
			out = append(out, []byte(hex.EncodeToString(quirked)))
		} else {
			out = append(out, []byte(strings.ToLower(ps)))
		}
	}
	return out, nil
}

// checkPasswordStrength scores password strength on a 0..10 scale.
func checkPasswordStrength(password string) int {
	score := 0
	if len(password) >= 8 {
		score += 2
	}
	if len(password) >= 12 {
		score += 2
	}
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if hasLower {
		score += 1
	}
	if hasUpper {
		score += 1
	}
	if hasDigit {
		score += 1
	}
	if hasSpecial {
		score += 1
	}
	if isHex64Plus(password) {
		score += 2
	}
	if score > 10 {
		score = 10
	}
	return score
}

var reHex64Plus = regexp.MustCompile(`^[0-9a-fA-F]{64,}$`)

func isHex64Plus(s string) bool { return reHex64Plus.MatchString(s) }

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
