package kdf

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// keyDeriveVector mirrors keyderive-vectors.json.
type keyDeriveVector struct {
	Name            string `json:"name"`
	Input           string `json:"input"`
	Password        string `json:"password"`
	SaltSeed        string `json:"saltSeed"`
	Strength        string `json:"strength"`
	Iterations      int    `json:"iterations"`
	MemorySize      int    `json:"memorySize"`
	Parallelism     int    `json:"parallelism"`
	HashLength      int    `json:"hashLength"`
	SaltArgon2idHex string `json:"saltArgon2idHex"`
	SaltPasswordHex string `json:"saltPasswordHex"`
	HMACKeyBytesHex string `json:"hmacKeyBytesHex"`
	InputSHA3       string `json:"inputSha3"`
	FinalSalt       string `json:"finalSalt"`
	MainKey         string `json:"mainKey"`
	S1              string `json:"s1"`
	S2              string `json:"s2"`
	S3              string `json:"s3"`
	UUID            string `json:"uuid"`
}

type keyDeriveVectorsFile struct {
	Vectors []keyDeriveVector `json:"vectors"`
}

func loadKeyDeriveVectors(t *testing.T) []keyDeriveVector {
	t.Helper()
	p := filepath.Join("..", "testvectors", "keyderive-vectors.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f keyDeriveVectorsFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("no keyderive vectors")
	}
	return f.Vectors
}

// TestUTF8DecodeBytes_Quirk verifies the WHATWG UTF-8 decoder against the
// frontend's array_buffer_to_string behaviour. This is the linchpin of the
// byte-level interop: the 64-byte saltPassword must decode to the exact
// string (with U+FFFD replacements) that the frontend uses as the HMAC key.
func TestUTF8DecodeBytes_Quirk(t *testing.T) {
	vectors := loadKeyDeriveVectors(t)
	for _, v := range vectors {
		rawBytes, err := hex.DecodeString(v.SaltPasswordHex)
		if err != nil {
			t.Fatalf("%s: decode saltPasswordHex: %v", v.Name, err)
		}
		// Decode with our WHATWG decoder, then re-encode to bytes for comparison.
		decoded := utf8DecodeBytes(rawBytes)
		reencoded := []byte(decoded)
		got := hex.EncodeToString(reencoded)
		if got != v.HMACKeyBytesHex {
			t.Errorf("%s: UTF-8 decode quirk mismatch\n  want (%d bytes): %s\n  got  (%d bytes): %s",
				v.Name, len(v.HMACKeyBytesHex)/2, v.HMACKeyBytesHex, len(got)/2, got)
		}
	}
}

// TestUTF8DecodeBytes_KnownSequences checks the decoder against a few
// hand-verified cases (independent of the golden vector file).
func TestUTF8DecodeBytes_KnownSequences(t *testing.T) {
	cases := []struct {
		name string
		in   string // hex
		want string // resulting string (as Go literal)
	}{
		{"pure ascii", "48656c6c6f", "Hello"},
		{"valid 2-byte", "c3a9", "é"},        // U+00E9
		{"valid 3-byte", "e4bda0", "\u4f60"}, // U+4F60
		{"single illegal 0x80", "80", "\ufffd"},
		{"single illegal 0xff", "ff", "\ufffd"},
		{"illegal lead c2 then invalid trail", "c27f", "\ufffd\u007f"}, // 0x7f < lower(0x80)
		{"truncated 2-byte lead only", "c3", "\ufffd"},
		{"truncated 3-byte lead + 1 trail", "e4bd", "\ufffd"},
		{"ascii mixed with illegal", "41ff42", "A\ufffdB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, err := hex.DecodeString(c.in)
			if err != nil {
				t.Fatalf("decode in: %v", err)
			}
			got := utf8DecodeBytes(in)
			if got != c.want {
				t.Errorf("mismatch\n  want: %q\n  got:  %q", c.want, got)
			}
		})
	}
}

// TestStrengthConfigFor_Default verifies tier resolution and fallback.
func TestStrengthConfigFor_Default(t *testing.T) {
	if cfg := StrengthConfigFor(StrengthMedium); cfg.Iterations != 8 || cfg.MemorySize != 1024*1024 {
		t.Errorf("medium mismatch: %+v", cfg)
	}
	if cfg := StrengthConfigFor(StrengthBasic); cfg.Iterations != 16 || cfg.MemorySize != 512*1024 {
		t.Errorf("basic mismatch: %+v", cfg)
	}
	if cfg := StrengthConfigFor(StrengthAdvanced); cfg.MemorySize != 1536*1024 {
		t.Errorf("advanced mismatch: %+v", cfg)
	}
	// Unknown / empty -> medium.
	if cfg := StrengthConfigFor(""); cfg.Iterations != 8 {
		t.Errorf("empty should fall back to medium, got %+v", cfg)
	}
	if cfg := StrengthConfigFor("nonsense"); cfg.Iterations != 8 {
		t.Errorf("unknown should fall back to medium, got %+v", cfg)
	}
}

// TestDeriveKeySet_GoldenVectors is the core interop test: it runs the full
// pipeline against the fixed golden vector and asserts S1/S2/S3/UUID match the
// frontend byte-for-byte. The basic tier allocates 512 MiB for Argon2id, so
// this test takes tens of seconds — it is skipped under -short.
func TestDeriveKeySet_GoldenVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Argon2id golden-vector test in -short mode")
	}
	vectors := loadKeyDeriveVectors(t)
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			r := DeriveKeySet(v.Input, []byte(v.Password), v.SaltSeed, Strength(v.Strength))
			if !r.Success {
				t.Fatalf("derive failed: %s", r.Error)
			}
			if len(r.Keys) != 3 {
				t.Fatalf("expected 3 keys, got %d", len(r.Keys))
			}
			if r.Keys[0] != v.S1 {
				t.Errorf("S1 mismatch\n  want: %s\n  got:  %s", v.S1, r.Keys[0])
			}
			if r.Keys[1] != v.S2 {
				t.Errorf("S2 mismatch\n  want: %s\n  got:  %s", v.S2, r.Keys[1])
			}
			if r.Keys[2] != v.S3 {
				t.Errorf("S3 mismatch\n  want: %s\n  got:  %s", v.S3, r.Keys[2])
			}
			if r.UUID != v.UUID {
				t.Errorf("UUID mismatch\n  want: %s\n  got:  %s", v.UUID, r.UUID)
			}
			// Sanity: UUID is 32 hex (16 bytes).
			if len(r.UUID) != 32 {
				t.Errorf("UUID length = %d, want 32", len(r.UUID))
			}
			// Sanity: each key is 128 hex (64 bytes).
			for i, k := range r.Keys {
				if len(k) != 128 {
					t.Errorf("key %d length = %d, want 128", i, len(k))
				}
			}
		})
	}
}

// TestDeriveKeySet_Deterministic verifies the same inputs yield the same
// output across two runs. Uses basic tier (still slow).
func TestDeriveKeySet_Deterministic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Argon2id determinism test in -short mode")
	}
	v := loadKeyDeriveVectors(t)[0]
	r1 := DeriveKeySet(v.Input, []byte(v.Password), v.SaltSeed, StrengthBasic)
	r2 := DeriveKeySet(v.Input, []byte(v.Password), v.SaltSeed, StrengthBasic)
	if !r1.Success || !r2.Success {
		t.Fatalf("derive failed: %s / %s", r1.Error, r2.Error)
	}
	if r1.UUID != r2.UUID {
		t.Errorf("UUID not deterministic: %s vs %s", r1.UUID, r2.UUID)
	}
	for i := range r1.Keys {
		if r1.Keys[i] != r2.Keys[i] {
			t.Errorf("key %d not deterministic", i)
		}
	}
}

// TestKeySetResult_KeysAreDistinct verifies the 3 derived keys differ from
// each other (domain separation works). Runs the cheap HKDF-only path by
// deriving from a fixed mainKey — but DeriveKeySet is the public API, so we
// just assert on a real (slow) result and trust -short to skip it in CI.
func TestKeySetResult_KeysAreDistinct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow distinctness test in -short mode")
	}
	v := loadKeyDeriveVectors(t)[0]
	r := DeriveKeySet(v.Input, []byte(v.Password), v.SaltSeed, StrengthBasic)
	if !r.Success {
		t.Fatalf("derive failed: %s", r.Error)
	}
	set := map[string]bool{}
	for _, k := range r.Keys {
		if set[k] {
			t.Errorf("duplicate key found: %s", truncate(k))
		}
		set[k] = true
	}
}

func truncate(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:8] + "…" + s[len(s)-8:]
}
