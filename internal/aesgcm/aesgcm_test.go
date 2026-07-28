package aesgcm

import (
	"bytes"
	"encoding/hex"
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// TDD: aesgcm package mirrors crypto/aes-gcm.ts.
// These tests verify the FULL key-derivation pipeline + AES-256-GCM against the
// reference implementation's golden vectors — the end-to-end byte-compatibility gate.

func TestGenerateAesGcmKey_FullPipeline_MatchesGolden(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	v := testvectors.MustLoad()
	g := v.GenerateAesGcmKey

	key, salt, err := GenerateAesGcmKey(g.Salt, g.Passwords)
	if err != nil {
		t.Fatalf("GenerateAesGcmKey error: %v", err)
	}
	if got := hex.EncodeToString(key); got != g.AesDEK {
		t.Errorf("aes_dek mismatch:\n got=%s\nwant=%s", got, g.AesDEK)
	}
	if got := hex.EncodeToString(salt); got != g.Sdata {
		t.Errorf("sdata mismatch:\n got=%s\nwant=%s", got, g.Sdata)
	}
}

func TestGcmEncryptWithIV_MatchesGolden(t *testing.T) {
	// Deterministic encryption with a fixed IV must reproduce the exact ciphertext.
	v := testvectors.MustLoad()
	g := v.GcmEncryptFixedIV

	key, err := hex.DecodeString(g.AesDEKHex)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString(g.SdataHex)
	if err != nil {
		t.Fatal(err)
	}
	iv, err := hex.DecodeString(g.IV)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(g.Plaintext)

	got, err := gcmEncryptWithIV(plaintext, key, salt, iv)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}
	if hex.EncodeToString(got) != g.Result {
		t.Errorf("gcmEncryptWithIV mismatch:\n got=%x\nwant=%s", got, g.Result)
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// Encrypt then decrypt with random IV must return the original plaintext.
	v := testvectors.MustLoad()
	g := v.GenerateAesGcmKey
	key, err := hex.DecodeString(g.AesDEK)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString(g.Sdata)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("round-trip test payload — CJK + emoji 🎉")

	enc, err := GcmEncrypt(plaintext, key, salt)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := GcmDecrypt(enc, key, salt)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Errorf("round-trip mismatch:\n got=%q\nwant=%q", dec, plaintext)
	}
}

func TestEncryptWithPassword_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	v := testvectors.MustLoad()
	salt := v.GenerateAesGcmKey.Salt
	passwords := []string{"weakpass", "Str0ng!Pass#2"}
	plaintext := []byte("password-based round trip")

	enc, err := EncryptWithPassword(plaintext, salt, passwords)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := DecryptWithPassword(enc, salt, passwords)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Errorf("round-trip mismatch:\n got=%q\nwant=%q", dec, plaintext)
	}
}

func TestEncryptWithPassword_InvalidInputs(t *testing.T) {
	salt := "ab"
	// empty data
	if _, err := EncryptWithPassword(nil, salt, []string{"p"}); err == nil {
		t.Error("expected error for empty data")
	}
	// empty passwords
	if _, err := EncryptWithPassword([]byte("x"), salt, nil); err == nil {
		t.Error("expected error for empty passwords")
	}
}

func TestGcmDecrypt_WrongPasswordFails(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	v := testvectors.MustLoad()
	salt := v.GenerateAesGcmKey.Salt
	plaintext := []byte("tamper detection test")
	enc, err := EncryptWithPassword(plaintext, salt, []string{"right-password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptWithPassword(enc, salt, []string{"wrong-password"}); err == nil {
		t.Error("expected GCM auth failure for wrong password")
	}
}
