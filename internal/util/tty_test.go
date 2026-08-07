package util

import "testing"

func TestWipeBytesZeroesFullCapacity(t *testing.T) {
	b := append([]byte("password"), make([]byte, 8)...)
	WipeBytes(b[:8])
	for _, c := range b {
		if c != 0 {
			t.Fatalf("byte not wiped: got %q, want 0", c)
		}
	}
}
