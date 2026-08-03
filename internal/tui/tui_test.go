package tui

import (
	"testing"
	"time"
)

// timedFake is a minimal TimedModel that records the timeouts it receives.
type timedFake struct {
	got []int
}

func (f *timedFake) Init() Cmd               { return nil }
func (f *timedFake) Update(Key) (Model, Cmd) { return f, nil }
func (f *timedFake) View() string            { return "" }
func (f *timedFake) UpdateTimeout(m TimeoutMsg) (Model, Cmd) {
	f.got = append(f.got, m.ID)
	return f, nil
}

func TestAfterDeliversTimeoutMsg(t *testing.T) {
	cmd := After(7, 10*time.Millisecond)
	got := cmd()
	tm, ok := got.(TimeoutMsg)
	if !ok {
		t.Fatalf("After command returned %T, want TimeoutMsg", got)
	}
	if tm.ID != 7 {
		t.Fatalf("ID: want 7, got %d", tm.ID)
	}
}

func TestBubbleModelRoutesTimeout(t *testing.T) {
	f := &timedFake{}
	got, cmd := bubbleModel{model: f}.Update(TimeoutMsg{ID: 3})
	if len(f.got) != 1 || f.got[0] != 3 {
		t.Fatalf("timed model received %v, want [3]", f.got)
	}
	if cmd != nil {
		t.Fatalf("unexpected command, got %v", cmd)
	}
	if _, ok := got.(bubbleModel); !ok {
		t.Fatalf("returned model type %T, want bubbleModel", got)
	}
}

// plainFake is a Model without TimedModel; timeouts must be dropped.
type plainFake struct{}

func (plainFake) Init() Cmd               { return nil }
func (plainFake) Update(Key) (Model, Cmd) { return plainFake{}, nil }
func (plainFake) View() string            { return "" }

func TestBubbleModelDropsTimeoutForPlainModel(t *testing.T) {
	got, cmd := bubbleModel{model: plainFake{}}.Update(TimeoutMsg{ID: 1})
	if cmd != nil {
		t.Fatalf("plain model must not produce a command, got %v", cmd)
	}
	if _, ok := got.(bubbleModel); !ok {
		t.Fatalf("returned model type %T, want bubbleModel", got)
	}
}
