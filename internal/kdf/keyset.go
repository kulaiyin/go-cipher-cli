package kdf

// This file implements DeriveKeySet, which replicates the frontend
// KeyDerivationForm.vue "derive key" pipeline (pipeline #1) byte-for-byte:
// derive a set of 3 × 512-bit keys (S1/S2/S3) plus a 128-bit UUID from
// (input, password, salt_seed, strength).
//
// Frontend reference:
// packages/web/src/components/KeyDerivationForm.vue:680-748
//
// The pipeline is deliberately distinct from DeriveSubKeyByDomain (pipeline
// #2, used by `enhance`). Do not mix the two.

import (
	"time"
	"unicode/utf8"

	"go-cipher-cli/internal/crypto"
	"go-cipher-cli/internal/safety"
)

// Strength is an Argon2id cost tier, mirroring the frontend strengthConfig
// (KeyDerivationForm.vue:546-572). "medium" is the default.
type Strength string

const (
	// StrengthBasic is the lowest tier (fastest).
	StrengthBasic Strength = "basic"
	// StrengthMedium is the default tier.
	StrengthMedium Strength = "medium"
	// StrengthAdvanced is the highest tier (slowest, most memory).
	StrengthAdvanced Strength = "advanced"
)

// StrengthConfig holds the Argon2id parameters for a Strength tier.
// MemorySize is in KiB. Values mirror the frontend strengthConfig exactly.
type StrengthConfig struct {
	Iterations  int
	MemorySize  int // KiB
	Parallelism int
	HashLength  int // bytes
}

// strengthConfigs mirrors frontend KeyDerivationForm.vue:552-572.
var strengthConfigs = map[Strength]StrengthConfig{
	StrengthBasic:    {Iterations: 16, MemorySize: 512 * 1024, Parallelism: 3, HashLength: 64}, // 512 MiB
	StrengthMedium:   {Iterations: 8, MemorySize: 1024 * 1024, Parallelism: 3, HashLength: 64}, // 1 GiB
	StrengthAdvanced: {Iterations: 5, MemorySize: 1536 * 1024, Parallelism: 3, HashLength: 64}, // 1.5 GiB
}

// StrengthConfigFor returns the config for the given tier. An empty or
// unrecognized value falls back to the default (medium), matching the
// frontend behaviour where selectedStrength defaults to "medium".
func StrengthConfigFor(s Strength) StrengthConfig {
	if cfg, ok := strengthConfigs[s]; ok {
		return cfg
	}
	return strengthConfigs[StrengthMedium]
}

// KeySetResult holds the derived key set plus echoed metadata.
type KeySetResult struct {
	Success        bool
	SaltSeed       string   // 128-hex (64 bytes)
	Keys           []string // S1, S2, S3 — each 128-hex (64 bytes / 512 bits)
	UUID           string   // 32-hex (16 bytes / 128 bits)
	Strength       Strength
	ProcessingTime int64 // milliseconds
	Error          string
}

// DeriveKeySet replicates the frontend KeyDerivationForm.deriveKey pipeline.
//
// Inputs are expected to be ALREADY cleaned (whitespace stripped + NFC), as
// the frontend does at KeyDerivationForm.vue:680-681. saltSeed is a 128-hex
// string (64 bytes). For "generate" mode pass a freshly generated salt; for
// "restore" mode pass the salt read from the recovery config.
//
// Output: 3 independent 512-bit keys and a 128-bit UUID, all deterministic
// for the same inputs.
func DeriveKeySet(input string, password []byte, saltSeed string, strength Strength) KeySetResult {
	start := time.Now()
	cfg := StrengthConfigFor(strength)
	result := KeySetResult{SaltSeed: saltSeed, Strength: normalizedStrength(strength)}

	// --- Step 1: derive the two salts from salt_seed (frontend L685-694) ---
	// Frontend: KeyDerivation.hkdf(salt_seed, { salt:"", info:"argon2id", hashLength:64 })
	//           KeyDerivation.hkdf(salt_seed, { salt:"", info:"password-salt", hashLength:64 })
	// salt_seed is consumed as its UTF-8 bytes (string -> toUint8Array). With an
	// empty salt the full HKDF (Extract+Expand, SHA3-512) runs. kdf.HKDF with
	// salt=[]byte{} matches this exactly.
	saltSeedBytes := []byte(saltSeed)
	saltArgon2id := HKDF(saltSeedBytes, []byte{}, []byte("argon2id"), cfg.HashLength)
	saltPassword := HKDF(saltSeedBytes, []byte{}, []byte("password-salt"), cfg.HashLength)

	// --- Step 2: strengthen the password (frontend L697-704) ---
	//
	// ⚠️ Frontend quirk #1 — "object coercion" (KeyDerivationForm.vue:697-699):
	//   const input_sha3 = CryptoTools.hashText(cleanedInput, "sha3-512")
	//   const combinedPassword = passwordInput + input_sha3
	// `CryptoTools.hashText` returns a Result OBJECT {success,data,...}, so the
	// string concatenation `passwordInput + input_sha3` evaluates to
	// `passwordInput + "[object Object]"` — the actual SHA3-512 hex is NEVER used
	// in combinedPassword. This is a latent frontend bug that has become part of
	// the byte-level contract; the Go side must replicate it exactly (the hash is
	// still computed by the frontend, but its value is discarded here).
	const objectCoercionLiteral = "[object Object]"
	combined := string(password) + objectCoercionLiteral
	_ = crypto.HashText(input, "sha3-512") // computed by frontend (side effect), value unused
	//
	// ⚠️ Frontend quirk #2 — "array_buffer_to_string" (KeyDerivationForm.vue:703):
	// the 64-byte saltPassword is passed through AesGcmTools.array_buffer_to_string,
	// i.e. a UTF-8 TextDecoder (WHATWG, error mode = replacement). Illegal byte
	// sequences become U+FFFD, so the re-encoded key differs from the raw bytes.
	// We must replicate the exact WHATWG decoding to stay byte-compatible.
	hmacKey := utf8DecodeBytes(saltPassword) // -> string with U+FFFD replacements
	finalSalt := crypto.HMAC(combined, "hmac-sha3-512", hmacKey).Data

	// --- Step 3: build the Argon2id input and derive the master key (L708-717) ---
	inputData := input + finalSalt + string(password)
	masterKey := Argon2([]byte(inputData), Argon2Config{
		Salt:        saltArgon2id,
		Iterations:  cfg.Iterations,
		MemorySize:  cfg.MemorySize,
		Parallelism: cfg.Parallelism,
		HashLength:  cfg.HashLength,
	})
	if !masterKey.Success || masterKey.Data == "" {
		result.Error = masterKey.Error
		result.ProcessingTime = time.Since(start).Milliseconds()
		return result
	}
	mainKeyHex := masterKey.Data // hex string; consumed as ASCII bytes below

	// --- Step 4: domain-separate 4 keys via HKDF (frontend L730-748) ---
	// Frontend: KeyDerivation.hkdf(mainKey, { salt:"", info:"S1"/"S2"/"S3"/"UUID" })
	// mainKey is the hex STRING, consumed as ASCII bytes (SafetyUtility.hkdf ->
	// toUint8Array(string) -> UTF-8 of the hex text). safety.HKDFExpand(prk string)
	// does exactly []byte(prk), so it matches.
	s1 := hexEncode(safety.HKDFExpand(mainKeyHex, []byte("S1"), cfg.HashLength))
	s2 := hexEncode(safety.HKDFExpand(mainKeyHex, []byte("S2"), cfg.HashLength))
	s3 := hexEncode(safety.HKDFExpand(mainKeyHex, []byte("S3"), cfg.HashLength))
	uuidFull := hexEncode(safety.HKDFExpand(mainKeyHex, []byte("UUID"), cfg.HashLength))
	uuid := uuidFull[:32] // first 32 hex chars = 16 bytes (frontend L746)

	result.Success = true
	result.Keys = []string{s1, s2, s3}
	result.UUID = uuid
	result.ProcessingTime = time.Since(start).Milliseconds()
	return result
}

// normalizedStrength returns the canonical Strength value, defaulting to medium.
func normalizedStrength(s Strength) Strength {
	if _, ok := strengthConfigs[s]; ok {
		return s
	}
	return StrengthMedium
}

func hexEncode(b []byte) string {
	return safety.BytesToHex(b)
}

// utf8DecodeBytes replicates the WHATWG Encoding Standard's UTF-8 decoder in
// "replacement" error mode (the mode used by browsers' TextDecoder and by
// Node's TextDecoder by default). Every illegal byte / incomplete sequence
// produces one U+FFFD (0xEF 0xBF 0xBD).
//
// This mirrors the frontend's AesGcmTools.array_buffer_to_string, which does
// `new TextDecoder().decode(uint8array)`. Go's standard library has no
// equivalent of the "replacement" error mode — strings.FromBytes/utf8.DecodeRune
// use different replacement rules — so we implement the WHATWG state machine
// directly. The output is the decoded string (possibly containing U+FFFD),
// which the caller then uses as a string key.
//
// Reference: https://encoding.spec.whatwg.org/#utf-8-decoder
func utf8DecodeBytes(input []byte) string {
	var b []byte // we build UTF-8 bytes directly; U+FFFD = ef bf bd
	const replacement = "\ufffd"

	var (
		codepoint uint32
		needed    int    // trail bytes still expected
		seen      int    // trail bytes seen so far
		lower     uint32 // lowest valid trail byte for current sequence
		upper     uint32 // highest valid trail byte for current sequence
	)
	const (
		stStart = iota
		stLead
	)

	state := stStart

	flushReplacement := func() {
		b = append(b, replacement...)
	}

	for i := 0; i < len(input); i++ {
		c := uint32(input[i])

		if state == stStart {
			if c <= 0x7F {
				b = append(b, byte(c))
				continue
			}
			if c >= 0xC2 && c <= 0xDF {
				codepoint = c & 0x1F
				needed = 1
				seen = 0
				lower = 0x80
				upper = 0xBF
				state = stLead
				continue
			}
			if c >= 0xE0 && c <= 0xEF {
				codepoint = c & 0x0F
				needed = 2
				seen = 0
				if c == 0xE0 {
					lower = 0xA0
				} else {
					lower = 0x80
				}
				if c == 0xED {
					upper = 0x9F
				} else {
					upper = 0xBF
				}
				state = stLead
				continue
			}
			if c >= 0xF0 && c <= 0xF4 {
				codepoint = c & 0x07
				needed = 3
				seen = 0
				if c == 0xF0 {
					lower = 0x90
				} else {
					lower = 0x80
				}
				if c == 0xF4 {
					upper = 0x8F
				} else {
					upper = 0xBF
				}
				state = stLead
				continue
			}
			// Invalid lead byte.
			flushReplacement()
			continue
		}

		// stLead: expecting a trail byte.
		if c >= lower && c <= upper {
			codepoint = (codepoint << 6) | (c & 0x3F)
			seen++
			lower = 0x80
			upper = 0xBF
			if seen >= needed {
				// Complete sequence; encode the codepoint as UTF-8.
				var buf [4]byte
				n := utf8.EncodeRune(buf[:], rune(codepoint))
				b = append(b, buf[:n]...)
				state = stStart
			}
			continue
		}

		// Invalid trail byte: emit one replacement, reprocess this byte from start.
		flushReplacement()
		state = stStart
		// Reprocess current byte at the start state (WHATWG spec).
		i--
	}

	// Trailing incomplete sequence at EOF -> one replacement.
	if state != stStart {
		flushReplacement()
	}

	return string(b)
}
