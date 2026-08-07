package util

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ReadPasswordTTY prompts on stderr and reads a password from the terminal with
// echo disabled via term.ReadPassword. The caller is responsible for wiping the
// returned bytes after use.
func ReadPasswordTTY(label string) ([]byte, error) {
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		WipeBytes(pw)
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	return bytes.TrimSpace(pw), nil
}

// WriteHexLine writes b as a lowercase hex line plus a newline to w, then
// wipes the buffer so the encoded bytes never linger. hex.EncodeToString is
// avoided because its returned string cannot be cleared.
func WriteHexLine(w io.Writer, b []byte) error {
	buf := make([]byte, hex.EncodedLen(len(b))+1)
	hex.Encode(buf[:len(buf)-1], b)
	buf[len(buf)-1] = '\n'
	defer WipeBytes(buf)
	_, err := w.Write(buf)
	return err
}

// WipeBytes zeroes b including its entire backing array.
func WipeBytes(b []byte) {
	clear(b[:cap(b)])
}
