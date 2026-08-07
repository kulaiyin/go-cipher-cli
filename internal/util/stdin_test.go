package util

import (
	"os"
	"testing"
)

func TestReadLinesStdin(t *testing.T) {
	old := os.Stdin
	defer func() { os.Stdin = old }()

	tests := []struct {
		name  string
		input string
		count int
		want  []string
	}{
		{"two lines", "alpha\nbeta\n", 2, []string{"alpha", "beta"}},
		{"trimmed", "  alpha  \n\tbeta\t\n", 2, []string{"alpha", "beta"}},
		{"early eof", "alpha\n", 2, []string{"alpha"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdin = r
			w.WriteString(tt.input)
			w.Close()

			lines, err := ReadLinesStdin(tt.count)
			r.Close()
			if err != nil {
				t.Fatalf("ReadLinesStdin: %v", err)
			}
			if len(lines) != len(tt.want) {
				t.Fatalf("got %d lines %q, want %d", len(lines), lines, len(tt.want))
			}
			for i, want := range tt.want {
				if string(lines[i]) != want {
					t.Errorf("line %d = %q, want %q", i, lines[i], want)
				}
			}
		})
	}
}
