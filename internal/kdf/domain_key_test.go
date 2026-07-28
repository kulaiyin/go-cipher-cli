package kdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// domainKeyVector mirrors the JSON structure in domain-key-vectors.json.
type domainKeyVector struct {
	Password   string `json:"password"`
	SaltSuffix string `json:"saltSuffix"`
	Domain     string `json:"domain"`
	SubKeyHex  string `json:"subKeyHex"`
}

func loadDomainKeyVectors(t *testing.T) []domainKeyVector {
	t.Helper()
	p := filepath.Join("..", "testvectors", "domain-key-vectors.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v []domainKeyVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestDeriveSubKeyByDomain_GoldenVectors(t *testing.T) {
	vectors := loadDomainKeyVectors(t)
	if len(vectors) < 6 {
		t.Fatalf("expected >= 6 vectors, got %d", len(vectors))
	}

	for _, v := range vectors {
		label := "password=" + v.Password + " salt_suffix=" + v.SaltSuffix + " domain=" + v.Domain
		t.Run(label, func(t *testing.T) {
			got, err := DeriveSubKeyByDomain(v.Password, v.SaltSuffix, v.Domain)
			if err != nil {
				t.Fatalf("derive error: %v", err)
			}
			if len(got) != 64 {
				t.Fatalf("expected 64-char hex (256 bit), got %d chars", len(got))
			}
			if got != v.SubKeyHex {
				t.Fatalf("mismatch:\n  got:      %s\n  expected: %s", got, v.SubKeyHex)
			}
		})
	}
}

func TestDeriveSubKey_Convenience(t *testing.T) {
	vectors := loadDomainKeyVectors(t)
	// Find the vector that matches DeriveSubKey's default domain and a known password.
	var target *domainKeyVector
	for i := range vectors {
		if vectors[i].Domain == DefaultDomain && vectors[i].Password == "weakpass" && vectors[i].SaltSuffix == "" {
			target = &vectors[i]
			break
		}
	}
	if target == nil {
		t.Fatal("could not find default-v1 / weakpass / empty suffix vector")
	}

	result := DeriveSubKey(target.Password, target.SaltSuffix)
	if !result.Success {
		t.Fatalf("derive failed: %s", result.Error)
	}
	if result.SubKeyHex != target.SubKeyHex {
		t.Fatalf("mismatch:\n  got:      %s\n  expected: %s", result.SubKeyHex, target.SubKeyHex)
	}
	if result.ProcessingTime <= 0 {
		t.Errorf("processing time should be > 0, got %d", result.ProcessingTime)
	}
}

func TestDeriveSubKeyByDomain_Deterministic(t *testing.T) {
	a, err := DeriveSubKeyByDomain("deterministic", "salt", "d")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveSubKeyByDomain("deterministic", "salt", "d")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("same inputs should produce same output: %s vs %s", a, b)
	}
}

func TestDeriveSubKeyByDomain_DifferentDomain(t *testing.T) {
	k1, err := DeriveSubKeyByDomain("pw", "s", "domain-a")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveSubKeyByDomain("pw", "s", "domain-b")
	if err != nil {
		t.Fatal(err)
	}
	if k1 == k2 {
		t.Fatal("different domains should produce different sub-keys")
	}
}

func TestDeriveSubKeyByDomain_DifferentSuffix(t *testing.T) {
	r1 := DeriveSubKey("pw", "suffix-a")
	r2 := DeriveSubKey("pw", "suffix-b")
	if !r1.Success || !r2.Success {
		t.Fatalf("derive failed: r1=%v r2=%v", r1.Error, r2.Error)
	}
	if r1.SubKeyHex == r2.SubKeyHex {
		t.Fatal("different salt suffixes should produce different sub-keys")
	}
}
