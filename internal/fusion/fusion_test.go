package fusion

import (
	"testing"

	"go-cipher-cli/internal/testvectors"
)

// TDD: fusion package mirrors password/fusion.ts.
// Tests first (Red), implementation in fusion.go (Green).

func TestNormalizePassword(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.NormalizePassword {
		got := NormalizePassword(c.In)
		if got != c.Out {
			t.Errorf("NormalizePassword(%q) = %q, want %q", c.In, got, c.Out)
		}
	}
	// Spot-check the two semantically-equal NFC forms collapse (the documented behaviour).
	if NormalizePassword("café") != NormalizePassword("cafe\u0301") {
		t.Errorf("NFC normalization mismatch: café != cafe\\u0301")
	}
}

func TestSafetyMergeStrings(t *testing.T) {
	// safety_merge_strings is the building block of fusePasswords.
	// A couple of direct cases pin down its behaviour independently of fusePasswords.
	cases := []struct {
		a, b, want string
	}{
		// equal-length interleave: a0 b0 a1 b1 ...
		{"abc", "123", "a1b2c3"},
		// a longer: interleave min(3) then append remainder of a with splice logic.
		// "abcde" + "123": min=3 -> [a,1,b,2,c,3], L=6; remaining = "de"
		//  i=1: insertPos=floor(6*1/3)%6 = 2%6=2 -> [a,1,d,b,2,c,3], L=7
		//  i=2: insertPos=floor(7*2/3)%7 = floor(4.66)=4%7=4 -> [a,1,d,b,e,2,c,3]
		{"abcde", "123", "a1dbe2c3"},
	}
	for _, c := range cases {
		if got := safetyMergeStrings(c.a, c.b); got != c.want {
			t.Errorf("safetyMergeStrings(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestFusePasswords_BasicGoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.FusePasswords.Basic {
		got := FusePasswords(c.Salt, c.Passwords)
		if got != c.Out {
			t.Errorf("FusePasswords(salt=%q) mismatch:\n got = %q\nwant = %q", c.Salt, got, c.Out)
		}
	}
}

func TestFusePasswords_ChineseGoldenVectors(t *testing.T) {
	v := testvectors.MustLoad()
	for _, c := range v.FusePasswords.Chinese {
		got := FusePasswords(c.Salt, c.Passwords)
		if got != c.Out {
			t.Errorf("FusePasswords(chinese, salt=%q) mismatch:\n got = %q\nwant = %q", c.Salt, got, c.Out)
		}
	}
}
