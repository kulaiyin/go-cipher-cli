// Package util provides small terminal helpers shared across commands.
package util

import (
	"os"

	"golang.org/x/term"
)

// colorEnabled is true when stdout is a terminal, so ANSI escape codes are
// only emitted for interactive output. When stdout is redirected (pipe, file,
// CI), all color functions return their input unchanged.
var colorEnabled = term.IsTerminal(int(os.Stdout.Fd()))

// paint wraps s in the given ANSI SGR code when color is enabled, otherwise
// returns s unchanged.
func paint(s, code string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Bold renders s with bold intensity.
func Bold(s string) string { return paint(s, "1") }

// Yellow renders s in yellow.
func Yellow(s string) string { return paint(s, "33") }

// Green renders s in green.
func Green(s string) string { return paint(s, "32") }

// Cyan renders s in cyan.
func Cyan(s string) string { return paint(s, "36") }

// Red renders s in red.
func Red(s string) string { return paint(s, "31") }
