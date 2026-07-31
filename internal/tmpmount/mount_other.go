//go:build !linux && !darwin

package tmpmount

import "fmt"

// mountNative reports that the platform has no native RAM filesystem
// mechanism; Mount then falls back to a plain directory.
func mountNative(_ string, _ int, _ string) (*Result, error) {
	return nil, fmt.Errorf("no native RAM filesystem support on this platform")
}

// mountNativeSudo reports the same lack of support for elevated mounts.
func mountNativeSudo(_ string, _ int, _ string) (*Result, error) {
	return nil, fmt.Errorf("no native RAM filesystem support on this platform")
}

// unmountNative is unreachable on unsupported platforms (Umount removes the
// plain-directory fallback instead), but must exist to satisfy the interface.
func unmountNative(_ string) error {
	return fmt.Errorf("no native RAM filesystem support on this platform")
}

// unmountNativeSudo reports the same lack of support for elevated unmounts.
func unmountNativeSudo(_ string) error {
	return fmt.Errorf("no native RAM filesystem support on this platform")
}

// isMountPoint always reports false on unsupported platforms.
func isMountPoint(_ string) bool { return false }
