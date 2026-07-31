//go:build linux

package tmpmount

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// mountNative mounts a tmpfs of sizeMB MiB at path via mount(8).
func mountNative(path string, sizeMB int, _ string) (*Result, error) {
	cmd := exec.Command("mount", "-t", "tmpfs", "-o", fmt.Sprintf("size=%dM", sizeMB), "tmpfs", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("tmpfs mount failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return &Result{Path: path, SizeMB: sizeMB, Backend: BackendTmpfs}, nil
}

// mountNativeSudo mounts tmpfs via sudo(8), used when the non-elevated mount
// failed due to insufficient privileges.
func mountNativeSudo(path string, sizeMB int, _ string) (*Result, error) {
	cmd := exec.Command("sudo", "mount", "-t", "tmpfs", "-o", fmt.Sprintf("size=%dM", sizeMB), "tmpfs", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sudo tmpfs mount failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return &Result{Path: path, SizeMB: sizeMB, Backend: BackendTmpfs}, nil
}

// unmountNative unmounts the filesystem at path via umount(8).
func unmountNative(path string) error {
	cmd := exec.Command("umount", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("umount failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unmountNativeSudo unmounts the filesystem at path via sudo umount(8), used
// when the non-elevated unmount failed due to insufficient privileges.
func unmountNativeSudo(path string) error {
	cmd := exec.Command("sudo", "umount", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sudo umount failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// isMountPoint reports whether path is a real mount point by inspecting
// /proc/self/mounts (requires no external tooling).
func isMountPoint(path string) bool {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}
	return false
}
