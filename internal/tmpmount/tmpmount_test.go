package tmpmount

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIsPrivilegeError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"en superuser", errors.New("mount: /tmp/x: must be superuser to use mount"), true},
		{"zh superuser", errors.New("mount: /tmp/x: \u5fc5\u987b\u4ee5\u8d85\u7ea7\u7528\u6237\u8eab\u4efd\u4f7f\u7528 mount"), true},
		{"permission denied", errors.New("operation not permitted: /dev/loop0"), true},
		{"unrelated", errors.New("mount: wrong fs type, bad option"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrivilegeError(tt.err); got != tt.want {
				t.Errorf("IsPrivilegeError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestDefaultMountPath(t *testing.T) {
	got := DefaultMountPath("default")
	want := filepath.Join(os.TempDir(), "mntemp", "default")
	if got != want {
		t.Errorf("DefaultMountPath(default) = %q, want %q", got, want)
	}
}

func TestCommandDir(t *testing.T) {
	dir, err := CommandDir("default", "key-derive")
	if err != nil {
		t.Fatalf("CommandDir: %v", err)
	}
	want := filepath.Join(os.TempDir(), "mntemp", "default", "key-derive")
	if dir != want {
		t.Errorf("CommandDir = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("CommandDir should create the directory: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("CommandDir(%q) is not a directory", dir)
	}
}

func TestIsMountedPlainDir(t *testing.T) {
	dir := t.TempDir()
	if IsMounted(dir) {
		t.Errorf("IsMounted(%q) = true for a plain directory", dir)
	}
	if IsMounted(filepath.Join(dir, "missing")) {
		t.Errorf("IsMounted returned true for a missing path")
	}
}
