package util

import (
	"bytes"
	"fmt"
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

// ReadPasswordTTYFromDevice prompts on stderr and reads a password from the
// controlling terminal (/dev/tty) with echo disabled. It must be used when
// stdin is a pipe so password input still comes from the interactive terminal.
// The caller is responsible for wiping the returned bytes after use.
func ReadPasswordTTYFromDevice(label string) ([]byte, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, err
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(int(tty.Fd()))
	if err != nil {
		WipeBytes(pw)
		return nil, err
	}
	fmt.Fprintln(os.Stderr)
	return bytes.TrimSpace(pw), nil
}

// WipeBytes zeroes b including its entire backing array.
func WipeBytes(b []byte) {
	clear(b[:cap(b)])
}
