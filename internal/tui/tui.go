// Package tui wraps bubbletea CLI operations.
//
// Upper layers (internal/form, cmd, etc.) interact only with the types
// defined in this package and never import bubbletea directly. When the
// underlying TUI framework is upgraded or replaced, only the internals of
// this package (bubbleModel adapter, key conversion) need to change.
package tui

import (
	"errors"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// errUnexpectedModel guards against a wrong final model type from Run.
var errUnexpectedModel = errors.New("tui: unexpected final model type")

// KeyType identifies the kind of a key event.
type KeyType int

const (
	// KeyRunes carries printable characters (CJK included) in the Runes field.
	KeyRunes KeyType = iota
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyEnter
	KeyBackspace
	KeyEsc
	KeyCtrlC
)

// Key is a framework-agnostic key event.
type Key struct {
	Type  KeyType
	Runes []rune
}

// Msg is an internal message produced by a Cmd. Upper layers normally do
// not handle it directly.
type Msg interface{}

// Cmd is a side-effect command, e.g. quitting the program.
type Cmd func() Msg

// TimeoutMsg is delivered to a model that scheduled a timeout with After.
// The ID identifies which scheduled timeout fired.
type TimeoutMsg struct {
	ID int
}

// TimedModel is an optional extension of Model: models that schedule
// timeouts via After implement UpdateTimeout to react to them.
type TimedModel interface {
	Model
	UpdateTimeout(TimeoutMsg) (Model, Cmd)
}

// After returns a command that delivers a TimeoutMsg with the given ID after
// d has elapsed. Several timeouts may run concurrently; the ID lets the model
// tell which one fired. Models implement TimedModel to handle the message.
func After(id int, d time.Duration) Cmd {
	return func() Msg {
		time.Sleep(d)
		return TimeoutMsg{ID: id}
	}
}

// Model is the minimal interface upper layers implement to render a TUI.
type Model interface {
	Init() Cmd
	Update(Key) (Model, Cmd)
	View() string
}

// quitMsg is the internal sentinel produced by Quit to stop the program.
type quitMsg struct{}

// Quit returns a command that stops the TUI program.
func Quit() Cmd {
	return func() Msg { return quitMsg{} }
}

// options holds the Run configuration.
type options struct {
	input  io.Reader
	output io.Writer
}

// Option configures how the TUI program runs.
type Option func(*options)

// WithInput sets the input source (default os.Stdin); used in tests to
// inject piped key bytes.
func WithInput(r io.Reader) Option {
	return func(o *options) { o.input = r }
}

// WithOutput sets the output target (default os.Stdout); used in tests to
// capture rendered frames.
func WithOutput(w io.Writer) Option {
	return func(o *options) { o.output = w }
}

func defaultOptions() options {
	return options{input: os.Stdin, output: os.Stdout}
}

// Run starts the TUI program and returns the final model. How the program
// exits is decided by the model itself (e.g. returning a Quit command or
// Ctrl+C).
func Run(model Model, opts ...Option) (Model, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	p := tea.NewProgram(bubbleModel{model: model}, tea.WithInput(o.input), tea.WithOutput(o.output))
	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	b, ok := final.(bubbleModel)
	if !ok {
		return nil, errUnexpectedModel
	}
	return b.model, nil
}

// bubbleModel adapts tui.Model to bubbletea.Model, hiding all bubbletea
// details from upper layers.
type bubbleModel struct {
	model Model
}

func (b bubbleModel) Init() tea.Cmd {
	return toBubbleCmd(b.model.Init())
}

func (b bubbleModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		m, cmd := b.model.Update(toTuiKey(msg))
		return bubbleModel{model: m}, toBubbleCmd(cmd)
	case TimeoutMsg:
		if tm, ok := b.model.(TimedModel); ok {
			m, cmd := tm.UpdateTimeout(msg)
			return bubbleModel{model: m}, toBubbleCmd(cmd)
		}
		return b, nil
	case tea.WindowSizeMsg:
		// Form layout does not depend on the window size.
		return b, nil
	default:
		return b, nil
	}
}

func (b bubbleModel) View() string {
	return b.model.View()
}

// toBubbleCmd converts a tui.Cmd to a bubbletea command; the Quit sentinel
// maps to tea.Quit.
func toBubbleCmd(c Cmd) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		msg := c()
		if _, ok := msg.(quitMsg); ok {
			return tea.Quit()
		}
		return msg
	}
}

// toTuiKey converts a bubbletea key event to the wrapped Key. Unknown keys
// (Tab and friends) yield an empty-Runes KeyRunes, which upper layers can
// safely ignore.
func toTuiKey(k tea.KeyMsg) Key {
	switch k.Type {
	case tea.KeyUp:
		return Key{Type: KeyUp}
	case tea.KeyDown:
		return Key{Type: KeyDown}
	case tea.KeyLeft:
		return Key{Type: KeyLeft}
	case tea.KeyRight:
		return Key{Type: KeyRight}
	case tea.KeyEnter:
		return Key{Type: KeyEnter}
	case tea.KeyBackspace:
		return Key{Type: KeyBackspace}
	case tea.KeyEsc:
		return Key{Type: KeyEsc}
	case tea.KeyCtrlC:
		return Key{Type: KeyCtrlC}
	default:
		return Key{Type: KeyRunes, Runes: k.Runes}
	}
}
