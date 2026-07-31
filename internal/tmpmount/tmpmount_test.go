package tmpmount

import (
	"errors"
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
