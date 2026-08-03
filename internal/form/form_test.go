package form

import (
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/tui"
)

func initTestI18n() {
	i18n.MustInit("")
	i18n.SetLanguage("en")
}

var smallSteps = [][]Step{
	{{ID: "Q01", Content: "First question"}, {ID: "Q02", Content: "Second question"}},
	{{ID: "Q03", Content: "Third question"}, {ID: "Q04", Content: "Fourth question"}},
}

func key(t tui.KeyType, runes ...rune) tui.Key {
	return tui.Key{Type: t, Runes: runes}
}

// press dispatches a key and asserts the program does not quit.
func press(t *testing.T, m *Model, k tui.Key) *Model {
	t.Helper()
	nm, cmd := m.Update(k)
	if cmd != nil {
		t.Fatalf("unexpected quit command for key %+v", k)
	}
	return nm.(*Model)
}

// drive dispatches a key sequence and asserts the program does not quit.
func drive(t *testing.T, m *Model, keys ...tui.Key) *Model {
	t.Helper()
	for _, k := range keys {
		m = press(t, m, k)
	}
	return m
}

func newSmall(opts ...Option) *Model {
	return New(smallSteps, append(opts, WithPageSize(2))...)
}

func TestNewDefaults(t *testing.T) {
	initTestI18n()
	m := New(smallSteps)
	if m.pageSize != defaultPageSize {
		t.Fatalf("default page size: want %d, got %d", defaultPageSize, m.pageSize)
	}
	if m.Stage() != StageSelect || m.Results() != nil {
		t.Fatalf("initial stage=%d results=%v", m.Stage(), m.Results())
	}
}

func TestSelectCursorNavigation(t *testing.T) {
	initTestI18n()
	m := newSmall()

	m = drive(t, m, key(tui.KeyDown))
	if m.cursor != 1 {
		t.Fatalf("after down: want cursor 1, got %d", m.cursor)
	}
	m = drive(t, m, key(tui.KeyDown))
	if m.cursor != 0 {
		t.Fatalf("after down wrap: want cursor 0, got %d", m.cursor)
	}
	m = drive(t, m, key(tui.KeyUp))
	if m.cursor != 1 {
		t.Fatalf("after up wrap: want cursor 1, got %d", m.cursor)
	}
}

func TestPagination(t *testing.T) {
	initTestI18n()
	step := make([]Step, 6)
	for i := range step {
		step[i] = Step{ID: "Q", Content: "x"}
	}
	m := New([][]Step{step}, WithPageSize(2))

	if m.pageCount() != 3 {
		t.Fatalf("want 3 pages, got %d", m.pageCount())
	}
	m = drive(t, m, key(tui.KeyRight))
	if m.page != 1 || m.cursor != 0 {
		t.Fatalf("after right: page=%d cursor=%d", m.page, m.cursor)
	}
	m = drive(t, m, key(tui.KeyRight), key(tui.KeyRight))
	if m.page != 0 {
		t.Fatalf("after right wrap: want page 0, got %d", m.page)
	}
	m = drive(t, m, key(tui.KeyLeft))
	if m.page != 2 {
		t.Fatalf("after left wrap: want page 2, got %d", m.page)
	}

	// The last page may be short: a cursor past the end clamps to the last item.
	m.page = 2
	m.cursor = 5
	m.clampCursor()
	if m.cursor != 1 {
		t.Fatalf("clamp: want cursor 1, got %d", m.cursor)
	}
}

func TestSelectEnterAndInput(t *testing.T) {
	initTestI18n()
	m := newSmall()

	m = drive(t, m, key(tui.KeyEnter))
	if m.Stage() != StageInput {
		t.Fatalf("after enter: want StageInput, got %d", m.Stage())
	}

	// Type the password (CJK included); Backspace deletes the last character.
	m = drive(t, m, key(tui.KeyRunes, '2', '0', '2', '4'), key(tui.KeyRunes, '\u5e74'))
	if got := string(m.input); got != "2024\u5e74" {
		t.Fatalf("input: want %q, got %q", "2024\u5e74", got)
	}
	m = drive(t, m, key(tui.KeyBackspace))
	if got := string(m.input); got != "2024" {
		t.Fatalf("after backspace: want %q, got %q", "2024", got)
	}

	// Enter moves to the confirm stage, not straight to the next step.
	m = drive(t, m, key(tui.KeyEnter))
	if m.Stage() != StageConfirm {
		t.Fatalf("after enter: want StageConfirm, got %d", m.Stage())
	}

	// Confirm with the same password to submit; moves to the next step.
	m = drive(t, m, key(tui.KeyRunes, '2', '0', '2', '4'), key(tui.KeyEnter))
	if m.Stage() != StageSelect || m.stepIdx != 1 {
		t.Fatalf("after submit: stage=%d step=%d", m.Stage(), m.stepIdx)
	}
	if m.currentItem().ID != "Q03" {
		t.Fatalf("step 2 first item: want Q03, got %s", m.currentItem().ID)
	}
}

func TestSkipConfirmSubmitsDirectly(t *testing.T) {
	initTestI18n()
	m := newSmall(WithSkipConfirm())

	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 's', 'e', 'c', 'r', 'e', 't'), key(tui.KeyEnter))
	if m.Stage() != StageSelect || m.stepIdx != 1 {
		t.Fatalf("skip confirm: want next step, got stage=%d step=%d", m.Stage(), m.stepIdx)
	}
	if len(m.results) != 1 || m.results[0].Answer != "secret" {
		t.Fatalf("results: want one submitted answer, got %+v", m.results)
	}
}

func TestPasswordMismatchResets(t *testing.T) {
	initTestI18n()
	m := newSmall()

	// Type the password, confirm with a different one: stays in input with an error.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 's', 'e', 'c', 'r', 'e', 't'), key(tui.KeyEnter))
	if m.Stage() != StageConfirm {
		t.Fatalf("want StageConfirm, got %d", m.Stage())
	}
	m = drive(t, m, key(tui.KeyRunes, 'd', 'i', 'f', 'f'), key(tui.KeyEnter))
	if m.Stage() != StageInput {
		t.Fatalf("mismatch: want StageInput, got %d", m.Stage())
	}
	if m.errMsg == "" || len(m.input) != 0 || len(m.confirm) != 0 {
		t.Fatalf("mismatch should set errMsg and clear buffers: err=%q input=%q confirm=%q", m.errMsg, string(m.input), string(m.confirm))
	}

	// Re-enter the same password twice to recover.
	m = drive(t, m, key(tui.KeyRunes, 's', 'e', 'c', 'r', 'e', 't'), key(tui.KeyEnter),
		key(tui.KeyRunes, 's', 'e', 'c', 'r', 'e', 't'), key(tui.KeyEnter))
	if m.Stage() != StageSelect || m.stepIdx != 1 {
		t.Fatalf("after recovery: stage=%d step=%d", m.Stage(), m.stepIdx)
	}
	if m.errMsg != "" {
		t.Fatalf("errMsg should be cleared after successful submit, got %q", m.errMsg)
	}
}

func TestInputEscCancels(t *testing.T) {
	initTestI18n()
	m := newSmall()

	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'x'), key(tui.KeyEsc))
	if m.Stage() != StageSelect {
		t.Fatalf("after esc in input: want StageSelect, got %d", m.Stage())
	}
	if len(m.input) != 0 || len(m.confirm) != 0 {
		t.Fatalf("buffers should be cleared, got input=%q confirm=%q", string(m.input), string(m.confirm))
	}

	// Esc in the confirm stage also cancels back to select.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'x'), key(tui.KeyEnter), key(tui.KeyRunes, 'y'), key(tui.KeyEsc))
	if m.Stage() != StageSelect {
		t.Fatalf("after esc in confirm: want StageSelect, got %d", m.Stage())
	}
}

func TestSubmitCompletesToSummary(t *testing.T) {
	initTestI18n()
	m := newSmall()

	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'a'), key(tui.KeyEnter), key(tui.KeyRunes, 'a'), key(tui.KeyEnter)) // step1
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'b'), key(tui.KeyEnter), key(tui.KeyRunes, 'b'), key(tui.KeyEnter)) // step2
	if m.Stage() != StageSummary {
		t.Fatalf("want StageSummary, got %d", m.Stage())
	}
	if len(m.Results()) != 2 {
		t.Fatalf("want 2 results, got %d", len(m.Results()))
	}
}

func TestEscBackToPreviousStep(t *testing.T) {
	initTestI18n()
	m := newSmall()

	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyEnter), key(tui.KeyEnter)) // step1 Q01 answered
	if m.stepIdx != 1 {
		t.Fatalf("want step 1 (0-based), got %d", m.stepIdx)
	}
	m = drive(t, m, key(tui.KeyEsc))
	if m.stepIdx != 0 {
		t.Fatalf("after esc: want step 0, got %d", m.stepIdx)
	}
	// Esc at the first step is a no-op.
	m = drive(t, m, key(tui.KeyEsc))
	if m.stepIdx != 0 {
		t.Fatalf("esc at first step should be no-op, got step %d", m.stepIdx)
	}
}

func TestResultsAndOverwrite(t *testing.T) {
	initTestI18n()
	m := newSmall()

	// Complete both steps normally.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'a'), key(tui.KeyEnter), key(tui.KeyRunes, 'a'), key(tui.KeyEnter))
	m = drive(t, m, key(tui.KeyDown), key(tui.KeyEnter), key(tui.KeyRunes, 'b'), key(tui.KeyEnter), key(tui.KeyRunes, 'b'), key(tui.KeyEnter))
	results := m.Results()
	if results[0].ID != "Q01" || results[0].Answer != "a" {
		t.Fatalf("result 0: %+v", results[0])
	}
	if results[1].ID != "Q04" || results[1].Answer != "b" {
		t.Fatalf("result 1: %+v", results[1])
	}

	// Go back to step one and re-answer; the old result is overwritten.
	m = drive(t, m, key(tui.KeyEsc), key(tui.KeyEsc), key(tui.KeyEnter), key(tui.KeyRunes, 'z'), key(tui.KeyEnter), key(tui.KeyRunes, 'z'), key(tui.KeyEnter))
	if len(m.Results()) != 2 {
		t.Fatalf("want 2 results, got %d", len(m.Results()))
	}
	if m.Results()[0].Answer != "z" || m.Results()[1].Answer != "b" {
		t.Fatalf("overwrite failed: %+v", m.Results())
	}
}

func TestSummaryQuitAndCtrlC(t *testing.T) {
	initTestI18n()
	m := newSmall()
	m = drive(t, m,
		key(tui.KeyEnter), key(tui.KeyEnter), key(tui.KeyEnter),
		key(tui.KeyEnter), key(tui.KeyEnter), key(tui.KeyEnter),
	)

	// On the summary: normal keys do not quit, Enter quits, Ctrl+C quits.
	_, cmd := m.Update(key(tui.KeyRunes, 'q'))
	if cmd != nil {
		t.Fatal("q on summary must not quit")
	}
	m = drive(t, m, key(tui.KeyRunes, 'x'))
	_, cmd = m.Update(key(tui.KeyEnter))
	if cmd == nil {
		t.Fatal("Enter on summary must quit")
	}
	_, cmd = m.Update(key(tui.KeyCtrlC))
	if cmd == nil {
		t.Fatal("Ctrl+C must quit")
	}
}

func TestViewStages(t *testing.T) {
	initTestI18n()
	m := newSmall()

	// Select stage
	view := m.View()
	for _, want := range []string{"Step 1/2", "(Page 1/1)", "Q01. First question", "▸ Q01"} {
		if !strings.Contains(view, want) {
			t.Errorf("select view missing %q:\n%s", want, view)
		}
	}

	// Input stage masks the password.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'h', 'i'))
	view = m.View()
	for _, want := range []string{"You selected: Q01 (First question)", "Please enter:", "**▌"} {
		if !strings.Contains(view, want) {
			t.Errorf("input view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "hi") {
		t.Errorf("input view must not leak the password:\n%s", view)
	}

	// Confirm stage asks again, still masked.
	m = drive(t, m, key(tui.KeyEnter))
	view = m.View()
	for _, want := range []string{"Please confirm:", "▌"} {
		if !strings.Contains(view, want) {
			t.Errorf("confirm view missing %q:\n%s", want, view)
		}
	}

	// Summary stage: confirm step1, then select/input/confirm step2.
	m = drive(t, m, key(tui.KeyRunes, 'h', 'i'), key(tui.KeyEnter),
		key(tui.KeyEnter), key(tui.KeyEnter), key(tui.KeyEnter))
	view = m.View()
	for _, want := range []string{"Result Summary", "Step | ID | Question | Answer", "1 | Q01 | First question | **", "Enter Continue  Hold r to show answers"} {
		if !strings.Contains(view, want) {
			t.Errorf("summary view missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "1 | Q01 | First question | hi") {
		t.Errorf("summary view must mask the password by default:\n%s", view)
	}
}

func TestSummaryHoldToReveal(t *testing.T) {
	initTestI18n()
	m := newSmall()
	m = drive(t, m,
		key(tui.KeyEnter), key(tui.KeyRunes, 'a'), key(tui.KeyEnter), key(tui.KeyRunes, 'a'), key(tui.KeyEnter),
		key(tui.KeyEnter), key(tui.KeyRunes, 'b'), key(tui.KeyEnter), key(tui.KeyRunes, 'b'), key(tui.KeyEnter),
	)
	if m.Stage() != StageSummary {
		t.Fatalf("want StageSummary, got %d", m.Stage())
	}

	// Masked by default.
	view := m.View()
	if !strings.Contains(view, "1 | Q01 | First question | *") {
		t.Errorf("summary must mask answers by default:\n%s", view)
	}
	if strings.Contains(view, "| a") {
		t.Errorf("summary must not leak the password:\n%s", view)
	}

	// Press r: answers are revealed and a hide timeout is scheduled.
	nm, cmd := m.Update(key(tui.KeyRunes, 'r'))
	if cmd == nil {
		t.Fatal("r on summary must schedule a hide timeout")
	}
	m = nm.(*Model)
	view = m.View()
	if !strings.Contains(view, "1 | Q01 | First question | a") {
		t.Errorf("summary must reveal answers while r is held:\n%s", view)
	}

	// OS key auto-repeat while r is held keeps the answers revealed and
	// reschedules the hide timeout on every repeat.
	var lastCmd tui.Cmd
	for i := 0; i < 3; i++ {
		nm, lastCmd = m.Update(key(tui.KeyRunes, 'r'))
		if lastCmd == nil {
			t.Fatal("repeated r must keep scheduling hide timeouts")
		}
		m = nm.(*Model)
	}
	view = m.View()
	if !strings.Contains(view, "1 | Q01 | First question | a") {
		t.Errorf("summary must stay revealed while r repeats:\n%s", view)
	}

	// A stale timeout (from an earlier press) must not hide the answers.
	nm, _ = m.UpdateTimeout(tui.TimeoutMsg{ID: m.revealGen - 1})
	m = nm.(*Model)
	view = m.View()
	if !strings.Contains(view, "1 | Q01 | First question | a") {
		t.Errorf("stale timeout must not hide the answers:\n%s", view)
	}

	// The latest timeout (key released, no more repeats) hides the answers.
	nm, _ = m.UpdateTimeout(tui.TimeoutMsg{ID: m.revealGen})
	m = nm.(*Model)
	view = m.View()
	if strings.Contains(view, "1 | Q01 | First question | a") {
		t.Errorf("timeout after release must hide the answers:\n%s", view)
	}
	if !strings.Contains(view, "1 | Q01 | First question | *") {
		t.Errorf("answers must be masked again after the timeout:\n%s", view)
	}
}

func TestStepFormatValidation(t *testing.T) {
	initTestI18n()
	steps := [][]Step{
		{{ID: "Q01", Content: "First", Validate: "digit8"}},
		{{ID: "Q02", Content: "Second", Validate: "nonempty"}},
		{{ID: "Q03", Content: "Third", Validate: "special"}},
	}
	m := New(steps, WithPageSize(2))

	// Step 1 (digit8): short input without a digit is rejected with a message.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, '1', '2', '3'), key(tui.KeyEnter))
	if m.Stage() != StageInput || m.errMsg == "" {
		t.Fatalf("digit8 short input: stage=%d err=%q", m.Stage(), m.errMsg)
	}
	// Re-enter cleanly and provide a valid 8-char digit-containing input.
	m = drive(t, m, key(tui.KeyEsc), key(tui.KeyEnter),
		key(tui.KeyRunes, 'a', 'b', 'c', 'd', 'e', 'f', 'g', '1'), key(tui.KeyEnter))
	if m.Stage() != StageConfirm {
		t.Fatalf("valid digit8: want StageConfirm, got %d", m.Stage())
	}
	m = drive(t, m, key(tui.KeyRunes, 'a', 'b', 'c', 'd', 'e', 'f', 'g', '1'), key(tui.KeyEnter))
	if m.stepIdx != 1 {
		t.Fatalf("step1 submit: want step 1, got %d", m.stepIdx)
	}

	// Step 2 (nonempty): empty input is rejected.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyEnter))
	if m.Stage() != StageInput || m.errMsg == "" {
		t.Fatalf("nonempty empty input: stage=%d err=%q", m.Stage(), m.errMsg)
	}
	m = drive(t, m, key(tui.KeyEsc), key(tui.KeyEnter), key(tui.KeyRunes, 'x'), key(tui.KeyEnter),
		key(tui.KeyRunes, 'x'), key(tui.KeyEnter))
	if m.stepIdx != 2 {
		t.Fatalf("step2 submit: want step 2, got %d", m.stepIdx)
	}

	// Step 3 (special): input without a special character is rejected.
	m = drive(t, m, key(tui.KeyEnter), key(tui.KeyRunes, 'a', 'b', 'c'), key(tui.KeyEnter))
	if m.Stage() != StageInput || m.errMsg == "" {
		t.Fatalf("special no-special input: stage=%d err=%q", m.Stage(), m.errMsg)
	}
	m = drive(t, m, key(tui.KeyEsc), key(tui.KeyEnter), key(tui.KeyRunes, 'a', 'b', '@'), key(tui.KeyEnter),
		key(tui.KeyRunes, 'a', 'b', '@'), key(tui.KeyEnter))
	if m.Stage() != StageSummary || len(m.Results()) != 3 {
		t.Fatalf("step3 submit: stage=%d results=%d", m.Stage(), len(m.Results()))
	}
}

func TestSummaryFinalPassword(t *testing.T) {
	initTestI18n()
	steps := [][]Step{
		{{ID: "Q01", Content: "First"}},
		{{ID: "Q02", Content: "Second"}},
	}
	m := New(steps, WithFinalPassword(func(results []Result) string {
		return strings.ToUpper(results[0].Answer + results[1].Answer)
	}))

	m = drive(t, m,
		key(tui.KeyEnter), key(tui.KeyRunes, 'a', 'a'), key(tui.KeyEnter), key(tui.KeyRunes, 'a', 'a'), key(tui.KeyEnter),
		key(tui.KeyEnter), key(tui.KeyRunes, 'b', 'b'), key(tui.KeyEnter), key(tui.KeyRunes, 'b', 'b'), key(tui.KeyEnter),
	)
	if m.Stage() != StageSummary {
		t.Fatalf("want StageSummary, got %d", m.Stage())
	}

	// Masked by default.
	view := m.View()
	if !strings.Contains(view, "Generated password: ****") {
		t.Errorf("summary must mask the final password:\n%s", view)
	}
	if strings.Contains(view, "AABB") {
		t.Errorf("summary must not leak the final password:\n%s", view)
	}

	// Hold r reveals it together with the answers.
	nm, _ := m.Update(key(tui.KeyRunes, 'r'))
	m = nm.(*Model)
	view = m.View()
	if !strings.Contains(view, "Generated password: AABB") {
		t.Errorf("summary must reveal the final password after r:\n%s", view)
	}
}

func TestEscInInputKeepsSelection(t *testing.T) {
	initTestI18n()
	m := newSmall()

	// Move to Q02, enter input, cancel with Esc: Q02 stays highlighted.
	m = drive(t, m, key(tui.KeyDown), key(tui.KeyEnter), key(tui.KeyRunes, 'x'), key(tui.KeyEsc))
	if m.Stage() != StageSelect || m.currentItem().ID != "Q02" {
		t.Fatalf("stage=%d current=%s", m.Stage(), m.currentItem().ID)
	}
}
