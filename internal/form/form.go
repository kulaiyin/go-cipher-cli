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
	"strings"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/tui"
)

// Step is a single selectable option (question).
type Step struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

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

// Model is the form's TUI model, implementing tui.Model.
type Model struct {
	steps    [][]Step
	stepIdx  int
	page     int // page within the current step
	cursor   int // cursor within the current page
	stage    Stage
	results  []Result
	input    []rune // password input buffer
	confirm  []rune // confirm-password buffer
	errMsg   string // validation error shown during input
	pageSize int
}

// Option configures the form behavior.
type Option func(*Model)

// WithPageSize sets the number of options per page (default 5).
func WithPageSize(n int) Option {
	return func(m *Model) { m.pageSize = n }
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
		if key.Type == tui.KeyRunes && len(key.Runes) > 0 && key.Runes[0] == 'q' {
			return m, tui.Quit()
		}
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
		} else {
			m.stage = StageConfirm
		}
	case tui.KeyEsc:
		m.input = nil
		m.confirm = nil
		m.stage = StageSelect
	}
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
		fmt.Fprintf(&sb, "%d | %s | %s | %s\n", r.Step, r.ID, r.Content, r.Answer)
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
