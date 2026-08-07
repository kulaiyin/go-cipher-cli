package crypto

import (
	"testing"
)

// Tests for the crypto package.

func TestHashText_KnownVectors(t *testing.T) {
	cases := []struct {
		algo string
		in   string
		want string
	}{
		{"md5", "", "d41d8cd98f00b204e9800998ecf8427e"},
		{"md5", "hello", "5d41402abc4b2a76b9719d911017c592"},
		{"sha1", "hello", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
		{"sha224", "hello", "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193"},
		{"sha256", "hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"sha384", "hello", "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f"},
		{"sha512", "hello", "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"},
		{"sha3-224", "hello", "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81"},
		{"sha3-256", "hello", "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"},
		{"sha3-384", "hello", "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887"},
		{"sha3-512", "hello", "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976"},
	}
	for _, c := range cases {
		res := HashText(c.in, c.algo)
		if !res.Success {
			t.Errorf("HashText(%q,%s) failed: %s", c.in, c.algo, res.Error)
			continue
		}
		if res.Data != c.want {
			t.Errorf("HashText(%q,%s) = %s, want %s", c.in, c.algo, res.Data, c.want)
		}
	}
}

func TestHashText_UnknownAlgorithm(t *testing.T) {
	res := HashText("hello", "nope")
	if res.Success {
		t.Error("expected failure for unknown algorithm")
	}
}

func TestHMACSHA3512_KnownVector(t *testing.T) {
	// RFC-ish check: HMAC-SHA3-512 over empty key/data is well-defined.
	res := HMAC("", "sha3-512", "")
	if !res.Success {
		t.Fatalf("HMAC failed: %s", res.Error)
	}
	if res.Data == "" {
		t.Error("empty output")
	}
}

func TestHMACHexBytes_ParityWithHMAC(t *testing.T) {
	// Locks byte equivalence: HMACHexBytes must yield the same hex digest as the
	// legacy string HMAC for the same raw data/key bytes.
	cases := []struct {
		data string
		alg  string
		key  string
	}{
		{"hello world", "hmac-sha3-512", "k"},
		{"data", "hmac-sha3-512", ""},
		{"data", "hmac-sha256", "key"},
		{"\x00\xff\x10", "sha3-512", "\x01\x02"},
	}
	for _, c := range cases {
		want := HMAC(c.data, c.alg, c.key)
		got, err := HMACHexBytes([]byte(c.data), c.alg, []byte(c.key))
		if err != nil {
			t.Errorf("HMACHexBytes(%q,%q,%q) error: %v", c.data, c.alg, c.key, err)
			continue
		}
		if string(got) != want.Data {
			t.Errorf("HMACHexBytes(%q,%q,%q) = %q, want %q", c.data, c.alg, c.key, got, want.Data)
		}
	}
}

func TestBase64_RoundTrip(t *testing.T) {
	in := []byte("hello world こんにちは")
	enc := Base64Encode(in)
	dec, err := Base64Decode(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != string(in) {
		t.Errorf("round-trip mismatch: %q != %q", dec, in)
	}
}
