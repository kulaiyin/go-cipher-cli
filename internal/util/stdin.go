package util

import (
	"bufio"
	"bytes"
	"io"
	"os"
)

// ReadLinesStdin reads up to count lines from stdin, trimming surrounding
// whitespace on each. Fewer lines are returned when EOF arrives early; the
// caller decides whether a missing line is an error or a fallback.
func ReadLinesStdin(count int) ([][]byte, error) {
	r := bufio.NewReader(os.Stdin)
	lines := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		raw, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		if len(raw) > 0 {
			lines = append(lines, bytes.TrimSpace(raw))
		}
		if err == io.EOF {
			break
		}
	}
	return lines, nil
}

// WipeLines zeroes every line including each line's entire backing array.
func WipeLines(lines [][]byte) {
	for _, l := range lines {
		WipeBytes(l)
	}
}
