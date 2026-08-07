// Package crypto provides text hashing across MD5/SHA1/SHA2/SHA3, HMAC, and
// Base64 helpers. It forwards the SHA3-512 / AES-GCM paths to internal/safety
// and internal/aesgcm.
package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/sha3"

	"go-cipher-cli/internal/i18n"
)

// Result is the unified success/error shape returned by the package.
type Result struct {
	Success        bool
	Data           string
	Error          string
	ProcessingTime int64
}

// HashText hashes s with the named algorithm and returns a hex digest.
// Supported: md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256,
// sha3-384, sha3-512.
func HashText(s, algorithm string) Result {
	h, err := newHash(algorithm)
	if err != nil {
		return Result{Error: err.Error()}
	}
	h.Write([]byte(s))
	return Result{Success: true, Data: hex.EncodeToString(h.Sum(nil))}
}

// HMAC computes HMAC over data with key using algorithm, returning a hex digest.
// algorithm accepts both "hmac-<hash>" names ("hmac-sha256", "hmac-sha3-512", ...)
// and the bare hash name ("sha256", "sha3-512", ...).
func HMAC(data, algorithm, key string) Result {
	name := strings.TrimPrefix(algorithm, "hmac-")
	fn, ok := hashFunc(name)
	if !ok {
		return Result{Error: i18n.TWithData("crypto.error.unsupported_hmac", map[string]interface{}{"Algorithm": algorithm})}
	}
	m := hmac.New(fn, []byte(key))
	m.Write([]byte(data))
	return Result{Success: true, Data: hex.EncodeToString(m.Sum(nil))}
}

// HMACBytes is the []byte-input counterpart of HMAC: it computes the same
// HMAC (same algorithm names, same hex digest) over raw data/key bytes, so
// callers that hold secrets as wipeable []byte need not materialize a string
// copy. HMACBytes(data, alg, key).Data == HMAC(string(data), alg, string(key)).Data.
func HMACBytes(data []byte, algorithm string, key []byte) Result {
	name := strings.TrimPrefix(algorithm, "hmac-")
	fn, ok := hashFunc(name)
	if !ok {
		return Result{Error: i18n.TWithData("crypto.error.unsupported_hmac", map[string]interface{}{"Algorithm": algorithm})}
	}
	m := hmac.New(fn, key)
	m.Write(data)
	return Result{Success: true, Data: hex.EncodeToString(m.Sum(nil))}
}

// HMACHexBytes returns the HMAC digest as the raw bytes of its lowercase hex
// encoding, so a caller that must zero every intermediate can wipe the returned
// slice (and the internal digest) instead of holding an immutable string.
// string(HMACHexBytes(data, alg, key)) == HMACBytes(data, alg, key).Data.
func HMACHexBytes(data []byte, algorithm string, key []byte) ([]byte, error) {
	name := strings.TrimPrefix(algorithm, "hmac-")
	fn, ok := hashFunc(name)
	if !ok {
		return nil, fmt.Errorf("%s", i18n.TWithData("crypto.error.unsupported_hmac", map[string]interface{}{"Algorithm": algorithm}))
	}
	m := hmac.New(fn, key)
	m.Write(data)
	raw := m.Sum(nil)
	out := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(out, raw)
	clear(raw)
	return out, nil
}

// Base64Encode returns the standard base64 encoding of b.
func Base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Base64Decode decodes a standard base64 string.
func Base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func newHash(algorithm string) (hash.Hash, error) {
	fn, ok := hashFunc(algorithm)
	if !ok {
		return nil, fmt.Errorf("%s", i18n.TWithData("crypto.error.unsupported_algo", map[string]interface{}{"Algorithm": algorithm}))
	}
	return fn(), nil
}

// hashFunc returns the constructor for a named algorithm.
func hashFunc(algorithm string) (func() hash.Hash, bool) {
	switch algorithm {
	case "md5":
		return md5.New, true
	case "sha1":
		return sha1.New, true
	case "sha224":
		return sha256.New224, true
	case "sha256":
		return sha256.New, true
	case "sha384":
		return sha512.New384, true
	case "sha512":
		return sha512.New, true
	case "sha3-224":
		return sha3.New224, true
	case "sha3-256":
		return sha3.New256, true
	case "sha3-384":
		return sha3.New384, true
	case "sha3-512":
		return sha3.New512, true
	}
	return nil, false
}
