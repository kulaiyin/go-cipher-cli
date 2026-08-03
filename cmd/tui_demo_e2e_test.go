package cmd

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/tui"
)

// TestTuiDemoFullFlow drives the real question pool (configs/hint-word-pools_en.json,
// 3 steps x 30 questions) through the whole interaction: page -> select -> type
// -> next step, then the summary screen, then quit with q.
func TestTuiDemoFullFlow(t *testing.T) {
	i18n.MustInit("")
	i18n.SetLanguage("en")

	steps, err := loadFormSteps("../configs/hint-word-pools_en.json")
	if err != nil {
		t.Fatalf("load pool: %v", err)
	}
	if len(steps) != 3 {
		t.Fatalf("want 3 steps, got %d", len(steps))
	}

	pr, pw := io.Pipe()
	defer pr.Close()
	var out bytes.Buffer

	done := make(chan *form.Model, 1)
	go func() {
		m, err := tui.Run(form.New(steps), tui.WithInput(pr), tui.WithOutput(&out))
		if err != nil {
			t.Errorf("tui run: %v", err)
			done <- nil
			return
		}
		done <- m.(*form.Model)
	}()

	feed := func(s string) {
		if _, err := pw.Write([]byte(s)); err != nil {
			t.Fatalf("write input: %v", err)
		}
		time.Sleep(80 * time.Millisecond)
	}

	feed("\r")       // step 1: select Q01 -> password input
	feed("20240101") // type password
	feed("\r")       // -> confirm password
	feed("20240101") // confirm
	feed("\r")       // submit -> step 2
	feed("\x1b[C")   // step 2: flip to page 2 (cursor on Q06)
	feed("\r")       // select Q06 -> password input
	feed("19991231") // type password
	feed("\r")       // -> confirm password
	feed("19991231") // confirm
	feed("\r")       // submit -> step 3
	feed("\r")       // step 3: select Q01 -> password input
	feed("abc123!")  // type password
	feed("\r")       // -> confirm password
	feed("abc123!")  // confirm
	feed("\r")       // submit -> summary
	feed("q")        // quit

	var m *form.Model
	select {
	case m = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("program did not quit in time")
	}
	pw.Close()

	if m == nil {
		t.Fatal("nil final model")
	}
	results := m.Results()
	if len(results) != 3 {
		t.Fatalf("want 3 results, got %d", len(results))
	}
	want := []struct {
		step, id, answer string
	}{
		{"1", "Q01", "20240101"},
		{"2", "Q06", "19991231"},
		{"3", "Q01", "abc123!"},
	}
	for i, w := range want {
		r := results[i]
		if r.Step != i+1 || r.ID != w.id || r.Answer != w.answer {
			t.Fatalf("result %d: got %+v, want step=%s id=%s answer=%s", i, r, w.step, w.id, w.answer)
		}
	}

	rendered := stripANSI(out.String())
	for _, wantStr := range []string{
		"Step 1/3", "(Page 1/6)",
		"Step 2/3", "(Page 2/6)",
		"Step 3/3",
		"Please enter:",
		"Result Summary",
		"1 | Q01 |",
		"2 | Q06 |",
		"3 | Q01 |",
		"q Quit  Hold r to show answers",
	} {
		if !strings.Contains(rendered, wantStr) {
			t.Errorf("rendered output missing %q\n--- output ---\n%s", wantStr, rendered)
		}
	}
}

func stripANSI(s string) string {
	var sb strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEsc = true
		case inEsc:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEsc = false
			}
		case r == '\r':
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
