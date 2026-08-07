package util

import (
	"bytes"
	"testing"
)

func TestWipeBytesZeroesFullCapacity(t *testing.T) {
	b := append([]byte("password"), make([]byte, 8)...)
	WipeBytes(b[:8])
	for _, c := range b {
		if c != 0 {
			t.Fatalf("byte not wiped: got %q, want 0", c)
		}
	}
}

func TestWriteHexLine(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHexLine(&buf, []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "deadbeef\n" {
		t.Errorf("got %q, want %q", got, "deadbeef\n")
	}
}
