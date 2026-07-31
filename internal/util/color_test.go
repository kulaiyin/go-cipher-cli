package util

import "testing"

func TestPaintDisabled(t *testing.T) {
	old := colorEnabled
	colorEnabled = false
	defer func() { colorEnabled = old }()

	for _, tc := range []struct {
		got string
	}{
		{Bold("x")}, {Yellow("x")}, {Green("x")}, {Cyan("x")}, {Red("x")},
	} {
		if tc.got != "x" {
			t.Errorf("color disabled: got %q, want %q", tc.got, "x")
		}
	}
}

func TestPaintEnabled(t *testing.T) {
	old := colorEnabled
	colorEnabled = true
	defer func() { colorEnabled = old }()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"bold", Bold("x"), "\x1b[1mx\x1b[0m"},
		{"yellow", Yellow("x"), "\x1b[33mx\x1b[0m"},
		{"green", Green("x"), "\x1b[32mx\x1b[0m"},
		{"cyan", Cyan("x"), "\x1b[36mx\x1b[0m"},
		{"red", Red("x"), "\x1b[31mx\x1b[0m"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %q, want %q", tt.name, tt.got, tt.want)
		}
	}
}
