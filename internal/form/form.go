// Package form provides a config-driven multi-step interactive form.
//
// The config is a nested structure: the outer array is the list of steps,
// the inner array is the list of options (questions) for each step. For
// every step the user pages through the options, picks one question, and
// types any text; steps can be revisited backwards, and after all steps
// are done a result summary is shown. The component is built on top of
// internal/tui and never imports bubbletea, so other commands (e.g.
// secret-seal) can integrate it freely.
package form

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/tui"
)

// Step is a single selectable option (question).
type Step struct {
	ID       string `json:"id"`
	Content  string `json:"content"`
	Validate string `json:"validate,omitempty"`
}

// specialCharRe matches the web tool's AT_LEAST_ONE_SPECIAL_CHAR class:
// ASCII punctuation plus CJK punctuation and currency symbols.
var specialCharRe = regexp.MustCompile("[" +
	"\u0021-\u002F\u003A-\u0040\u005B-\u0060\u007B-\u007E" +
	"\u3000-\u303F\uFF00-\uFFEF" +
	"\u2026\u00B7\u2014\u2013\u201C\u201D\u2018\u2019\u3001" +
	"€£₹₽₩฿₺₴₦₵₫₭₪₼₲₳₸₺֏₢₣₤₥₧₨₩₪₫₭₮₯₰₲₳₴₵﷼¢₠₢₣₤₧₺₼₽₿ΞÐŁ" +
	"]")

// Result is the final answer for one step.
type Result struct {
	Step    int    // 1-based step number
	ID      string // ID of the chosen question
	Content string // text of the chosen question
	Answer  string // user input
}

// Stage is the interaction phase of the form.
type Stage int

const (
	// StageSelect: page through options and pick one.
	StageSelect Stage = iota
	// StageInput: type a password (masked) for the chosen question.
	StageInput
	// StageConfirm: re-type the password; must match before submitting.
	StageConfirm
	// StageSummary: show all results; press q to quit.
	StageSummary
)

// defaultPageSize is the number of options shown per page.
const defaultPageSize = 5

// revealHoldDelay is the hide timeout after the last 'r' key event. Terminals
// only report key presses, not releases; while a key is held the OS key
// auto-repeat keeps sending the same key (~30ms apart), and each event
// restarts this timer. The window must exceed the OS first-repeat delay
// (~500ms) or the reveal would flicker while the key is held, so the answers
// hide roughly revealHoldDelay after the key is released.
const revealHoldDelay = 600 * time.Millisecond

// Model is the form's TUI model, implementing tui.Model.
type Model struct {
	steps     [][]Step
	stepIdx   int
	page      int // page within the current step
	cursor    int // cursor within the current page
	stage     Stage
	results   []Result
	input     []rune // password input buffer
	confirm   []rune // confirm-password buffer
	errMsg    string // validation error shown during input
	pageSize  int
	reveal    bool // summary: answers shown in plaintext while r is held
	revealGen int  // generation of the latest reveal timeout; stale ones ignored

	finalPasswordFn func([]Result) string // optional final-password generator
	finalPassword   string                // cached result, shown on the summary

	skipConfirm bool // submit after a single input, skipping the re-type stage
}

// Option configures the form behavior.
type Option func(*Model)

// WithPageSize sets the number of options per page (default 5).
func WithPageSize(n int) Option {
	return func(m *Model) { m.pageSize = n }
}

// WithFinalPassword sets a generator that derives a final password from the
// collected answers; when set, the summary screen shows the result (masked,
// hold r to reveal).
func WithFinalPassword(fn func([]Result) string) Option {
	return func(m *Model) { m.finalPasswordFn = fn }
}

// WithSkipConfirm submits each answer after a single input, skipping the
// re-type confirmation stage (used by restore flows that re-answer the
// questions that generated a password).
func WithSkipConfirm() Option {
	return func(m *Model) { m.skipConfirm = true }
}

// New creates a form model.
func New(steps [][]Step, opts ...Option) *Model {
	m := &Model{steps: steps, pageSize: defaultPageSize}
	for _, opt := range opts {
		opt(m)
	}
	if m.pageSize < 1 {
		m.pageSize = 1
	}
	return m
}

// Init implements tui.Model.
func (m *Model) Init() tui.Cmd { return nil }

// Update handles a key event, implementing tui.Model.
func (m *Model) Update(key tui.Key) (tui.Model, tui.Cmd) {
	if key.Type == tui.KeyCtrlC {
		return m, tui.Quit()
	}

	switch m.stage {
	case StageSelect:
		m.handleSelectKey(key)
	case StageInput:
		m.handleInputKey(key, false)
	case StageConfirm:
		m.handleInputKey(key, true)
	case StageSummary:
		if key.Type == tui.KeyEsc && len(m.steps) > 0 {
			// Allow re-answering the last step from the summary.
			m.stage = StageSelect
			m.stepIdx = len(m.steps) - 1
			m.page = 0
			m.cursor = 0
			return m, nil
		}
		if key.Type == tui.KeyEnter {
			return m, tui.Quit()
		}
		if key.Type == tui.KeyRunes && len(key.Runes) > 0 {
			switch key.Runes[0] {
			case 'r':
				return m.showAnswers()
			}
		}
	}
	return m, nil
}

// showAnswers reveals the summary answers and schedules a hide timeout.
// While r is held, OS key auto-repeat keeps delivering 'r' events and each
// one reschedules the timeout; the last one fires revealHoldDelay after the
// key is released, hiding the answers again.
func (m *Model) showAnswers() (tui.Model, tui.Cmd) {
	m.reveal = true
	m.revealGen++
	return m, tui.After(m.revealGen, revealHoldDelay)
}

// UpdateTimeout implements tui.TimedModel: a fired timeout hides the answers
// unless a newer 'r' press has already rescheduled it.
func (m *Model) UpdateTimeout(msg tui.TimeoutMsg) (tui.Model, tui.Cmd) {
	if msg.ID == m.revealGen {
		m.reveal = false
	}
	return m, nil
}

// View renders the current screen, implementing tui.Model.
func (m *Model) View() string {
	switch m.stage {
	case StageSelect:
		return m.selectView()
	case StageInput, StageConfirm:
		return m.inputView()
	case StageSummary:
		return m.summaryView()
	}
	return ""
}

// Results returns the results of all steps, in step order.
func (m *Model) Results() []Result {
	return m.results
}

// Stage returns the current stage.
func (m *Model) Stage() Stage {
	return m.stage
}

// Run is a convenience entry point: it runs the form and returns the
// results. Prefer it when integrating into other commands; use tui.Run
// directly only when a custom runtime (e.g. injected test IO) is needed.
func Run(steps [][]Step, opts ...Option) ([]Result, error) {
	m, err := tui.Run(New(steps, opts...))
	if err != nil {
		return nil, err
	}
	return m.(*Model).Results(), nil
}

// --- key handling ---

func (m *Model) handleSelectKey(key tui.Key) {
	switch key.Type {
	case tui.KeyUp:
		if n := m.pageItemCount(); n > 0 {
			m.cursor = (m.cursor - 1 + n) % n
		}
	case tui.KeyDown:
		if n := m.pageItemCount(); n > 0 {
			m.cursor = (m.cursor + 1) % n
		}
	case tui.KeyLeft:
		if pages := m.pageCount(); pages > 1 {
			m.page = (m.page - 1 + pages) % pages
			m.clampCursor()
		}
	case tui.KeyRight:
		if pages := m.pageCount(); pages > 1 {
			m.page = (m.page + 1) % pages
			m.clampCursor()
		}
	case tui.KeyEnter:
		m.stage = StageInput
		m.input = nil
		m.errMsg = ""
	case tui.KeyEsc:
		if m.stepIdx > 0 {
			m.stepIdx--
			// Completed results are kept; re-answering overwrites them later.
			m.page = 0
			m.cursor = 0
		}
	}
}

func (m *Model) handleInputKey(key tui.Key, confirm bool) {
	switch key.Type {
	case tui.KeyRunes:
		if confirm {
			m.confirm = append(m.confirm, key.Runes...)
		} else {
			m.input = append(m.input, key.Runes...)
		}
	case tui.KeyBackspace:
		if confirm {
			if len(m.confirm) > 0 {
				m.confirm = m.confirm[:len(m.confirm)-1]
			}
		} else if len(m.input) > 0 {
			m.input = m.input[:len(m.input)-1]
		}
	case tui.KeyEnter:
		if confirm {
			m.confirmPassword()
		} else if errMsg := m.stepInputError(); errMsg != "" {
			m.errMsg = errMsg
		} else if m.skipConfirm {
			m.submit()
		} else {
			m.stage = StageConfirm
		}
	case tui.KeyEsc:
		m.input = nil
		m.confirm = nil
		m.stage = StageSelect
	}
}

// stepInputError validates the current input against the selected step's
// format rule (trimmed of surrounding whitespace), mirroring the web tool's
// per-step password rules. It returns a localized message or "" when valid.
func (m *Model) stepInputError() string {
	rule := m.currentItem().Validate
	if rule == "" {
		return ""
	}
	trimmed := strings.TrimSpace(string(m.input))
	switch rule {
	case "digit8":
		if len([]rune(trimmed)) < 8 || !strings.ContainsAny(trimmed, "0123456789") {
			return i18n.T("form.error.step1_digit8")
		}
	case "nonempty":
		if trimmed == "" {
			return i18n.T("form.error.step2_nonempty")
		}
	case "special":
		if !specialCharRe.MatchString(trimmed) {
			return i18n.T("form.error.step3_special")
		}
	}
	return ""
}

// confirmPassword submits the answer when the two password entries match;
// otherwise it resets both buffers and shows a mismatch error.
func (m *Model) confirmPassword() {
	if string(m.input) == string(m.confirm) {
		m.submit()
		return
	}
	m.errMsg = i18n.T("form.password_mismatch")
	m.input = nil
	m.confirm = nil
	m.stage = StageInput
}

func (m *Model) submit() {
	item := m.currentItem()
	r := Result{
		Step:    m.stepIdx + 1,
		ID:      item.ID,
		Content: item.Content,
		Answer:  string(m.input),
	}
	if m.stepIdx < len(m.results) {
		m.results[m.stepIdx] = r
	} else {
		m.results = append(m.results, r)
	}
	m.input = nil
	m.confirm = nil
	m.errMsg = ""
	m.stepIdx++
	if m.stepIdx >= len(m.steps) {
		m.stage = StageSummary
		// A fresh summary is always masked; bump the generation so a
		// pending hide timeout from a previous summary cannot fire here.
		m.reveal = false
		m.revealGen++
		m.finalPassword = ""
		if m.finalPasswordFn != nil {
			m.finalPassword = m.finalPasswordFn(m.results)
		}
	} else {
		m.page = 0
		m.cursor = 0
		m.stage = StageSelect
	}
}

// --- paging & cursor ---

// pageCount returns the number of pages for the current step.
func (m *Model) pageCount() int {
	total := len(m.steps[m.stepIdx])
	if total == 0 {
		return 0
	}
	return (total + m.pageSize - 1) / m.pageSize
}

// pageItemCount returns the number of options on the current page; the
// last page may be shorter.
func (m *Model) pageItemCount() int {
	total := len(m.steps[m.stepIdx])
	start := m.page * m.pageSize
	if start >= total {
		return 0
	}
	if remaining := total - start; remaining < m.pageSize {
		return remaining
	}
	return m.pageSize
}

func (m *Model) clampCursor() {
	if n := m.pageItemCount(); n > 0 && m.cursor >= n {
		m.cursor = n - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

// currentItem returns the currently highlighted question; valid in both
// the select and input stages.
func (m *Model) currentItem() Step {
	idx := m.page*m.pageSize + m.cursor
	if idx < 0 || idx >= len(m.steps[m.stepIdx]) {
		return Step{}
	}
	return m.steps[m.stepIdx][idx]
}

// --- views ---

func (m *Model) selectView() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", i18n.T("form.title"))
	fmt.Fprintf(&sb, "%s %s\n\n", stepIndicator(m.stepIdx, len(m.steps)), pageIndicator(m.page, m.pageCount()))

	for i := 0; i < m.pageItemCount(); i++ {
		item := m.steps[m.stepIdx][m.page*m.pageSize+i]
		marker := "  "
		if i == m.cursor {
			marker = "▸ "
		}
		fmt.Fprintf(&sb, "%s%s. %s\n", marker, item.ID, item.Content)
	}
	fmt.Fprintf(&sb, "\n%s", i18n.T("form.footer_select"))
	return sb.String()
}

func (m *Model) inputView() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n\n", stepIndicator(m.stepIdx, len(m.steps)))
	fmt.Fprintf(&sb, "%s\n\n", i18n.TWithData("form.selected", map[string]interface{}{
		"ID":      m.currentItem().ID,
		"Content": m.currentItem().Content,
	}))
	if m.errMsg != "" {
		fmt.Fprintf(&sb, "%s\n", m.errMsg)
	}
	if m.stage == StageConfirm {
		fmt.Fprintf(&sb, "%s %s▌\n\n", i18n.T("form.confirm_prompt"), mask(m.confirm))
		fmt.Fprintf(&sb, "%s", i18n.T("form.confirm_footer"))
	} else {
		fmt.Fprintf(&sb, "%s %s▌\n\n", i18n.T("form.input_prompt"), mask(m.input))
		fmt.Fprintf(&sb, "%s", i18n.T("form.input_footer"))
	}
	return sb.String()
}

// mask renders runes as asterisks, hiding the password content.
func mask(runes []rune) string {
	if len(runes) == 0 {
		return ""
	}
	return strings.Repeat("*", len(runes))
}

func (m *Model) summaryView() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n\n", i18n.T("form.summary_title"))
	fmt.Fprintf(&sb, "%s | %s | %s | %s\n", i18n.T("form.summary_col_step"), i18n.T("form.summary_col_id"), i18n.T("form.summary_col_content"), i18n.T("form.summary_col_answer"))
	for _, r := range m.results {
		answer := r.Answer
		if !m.reveal {
			answer = mask([]rune(r.Answer))
		}
		fmt.Fprintf(&sb, "%d | %s | %s | %s\n", r.Step, r.ID, r.Content, answer)
	}
	if m.finalPassword != "" {
		pw := m.finalPassword
		if !m.reveal {
			pw = mask([]rune(m.finalPassword))
		}
		fmt.Fprintf(&sb, "\n%s: %s\n", i18n.T("form.summary_final_password"), pw)
	}
	fmt.Fprintf(&sb, "\n%s", i18n.T("form.summary_footer"))
	return sb.String()
}

func stepIndicator(current, total int) string {
	return i18n.TWithData("form.step_indicator", map[string]interface{}{
		"Current": current + 1,
		"Total":   total,
	})
}

func pageIndicator(current, total int) string {
	return i18n.TWithData("form.page_indicator", map[string]interface{}{
		"Current": current + 1,
		"Total":   total,
	})
}
