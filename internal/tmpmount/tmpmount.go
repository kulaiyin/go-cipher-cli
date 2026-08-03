// Package tmpmount mounts RAM-backed temporary filesystems.
//
// The native mechanism is platform-dependent: tmpfs via mount(8) on Linux, a
// RAM disk via hdiutil(1) on macOS. When the platform provides no native
// mechanism, or the mount attempt fails (e.g. missing privileges), Mount
// falls back to creating a plain directory so the CLI stays usable anywhere.
package tmpmount

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Backend identifies how a mount was realized.
type Backend string

const (
	// BackendTmpfs is a Linux tmpfs mount (RAM-backed).
	BackendTmpfs Backend = "tmpfs"
	// BackendRamDisk is a macOS RAM disk volume (RAM-backed).
	BackendRamDisk Backend = "ramdisk"
	// BackendDir is a plain directory fallback (not RAM-backed).
	BackendDir Backend = "dir"
)

// Result describes the outcome of a Mount call.
type Result struct {
	Path        string
	SizeMB      int
	Backend     Backend
	FallbackErr error // reason the native mount was not used; nil for native backends
}

// DefaultMountPath returns the default mount root for a named volatile
// filesystem: <os.TempDir()>/mntemp/<name>.
func DefaultMountPath(name string) string {
	return filepath.Join(os.TempDir(), "mntemp", name)
}

// IsMounted reports whether path is currently a real mount point (e.g. a Linux
// tmpfs or macOS RAM disk). Plain directories report false.
func IsMounted(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return isMountPoint(path)
}

// CommandDir returns the per-command directory under the named mount root
// (<root>/<command>) and creates it if missing.
func CommandDir(name, command string) (string, error) {
	dir := filepath.Join(DefaultMountPath(name), command)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// Mount creates a RAM-backed temporary filesystem at path with the given size
// in MiB. It creates path if needed, tries the platform-native mechanism, and
// falls back to a plain directory when that is unavailable or fails. The
// returned Result always has a non-nil Path; errors are reserved for failures
// that prevent any usable mount (e.g. directory creation).
func Mount(path string, sizeMB int, name string) (*Result, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("create mount directory: %w", err)
	}

	res, err := mountNative(path, sizeMB, name)
	if err == nil {
		return res, nil
	}
	// Fallback: the directory already exists, so the mount is still usable.
	return &Result{Path: path, SizeMB: sizeMB, Backend: BackendDir, FallbackErr: err}, nil
}

// MountWithSudo retries the native mount elevated via sudo(8). On platforms
// with no privilege-gated native mechanism it returns an error. The caller
// decides whether sudo is warranted (e.g. via IsPrivilegeError).
func MountWithSudo(path string, sizeMB int, name string) (*Result, error) {
	res, err := mountNativeSudo(path, sizeMB, name)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// IsPrivilegeError reports whether err is a mount(8)-style failure caused by
// insufficient privileges (e.g. "must be superuser to use mount").
func IsPrivilegeError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"must be superuser",        // en
		"superuser",                // en, shorter variant
		"\u8d85\u7ea7\u7528\u6237", // zh: mount(8) superuser message under zh locale
		"permission denied",        // en
		"operation not permitted",  // en
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// UmountWithSudo detaches the RAM-backed filesystem at path elevated via
// sudo(8), mirroring Umount for when the non-elevated attempt fails on
// insufficient privileges.
func UmountWithSudo(path string) error {
	if isMountPoint(path) {
		if err := unmountNativeSudo(path); err != nil {
			return fmt.Errorf("unmount %s: %w", path, err)
		}
		// The mount point directory may remain after unmounting; drop it if empty.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove mount point: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove directory: %w", err)
	}
	return nil
}

// Umount detaches the RAM-backed filesystem at path when it is a real mount
// point, or removes the plain-directory fallback otherwise. Directories are
// only removed when empty; non-empty contents are left for the user to clean
// up (never recursive, since path may point anywhere).
func Umount(path string) error {
	if isMountPoint(path) {
		if err := unmountNative(path); err != nil {
			return fmt.Errorf("unmount %s: %w", path, err)
		}
		// The mount point directory may remain after unmounting; drop it if empty.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove mount point: %w", err)
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove directory: %w", err)
	}
	return nil
}
