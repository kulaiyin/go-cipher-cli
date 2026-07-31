//go:build darwin

package tmpmount

import (
	"fmt"
	"os/exec"
	"strings"
)

// mountNative creates a RAM disk of sizeMB MiB via hdiutil(1) and mounts it as
// a volume named after name. macOS mounts the volume at /Volumes/<name>
// regardless of the requested path.
func mountNative(_ string, sizeMB int, name string) (*Result, error) {
	// 512-byte sectors; 1 MiB = 2048 sectors.
	sectors := sizeMB * 2048
	attach, err := exec.Command("hdiutil", "attach", "-nomount", fmt.Sprintf("ram://%d", sectors)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("hdiutil attach failed: %w: %s", err, strings.TrimSpace(string(attach)))
	}
	device := strings.Fields(string(attach))[0]

	erase, err := exec.Command("diskutil", "eraseVolume", "HFS+", name, device).CombinedOutput()
	if err != nil {
		_ = exec.Command("hdiutil", "detach", device).Run()
		return nil, fmt.Errorf("diskutil eraseVolume failed: %w: %s", err, strings.TrimSpace(string(erase)))
	}
	return &Result{Path: "/Volumes/" + name, SizeMB: sizeMB, Backend: BackendRamDisk}, nil
}

// mountNativeSudo is not needed on macOS: hdiutil(1) RAM disks do not require
// elevated privileges, so MountWithSudo simply reuses the native path.
func mountNativeSudo(path string, sizeMB int, name string) (*Result, error) {
	return mountNative(path, sizeMB, name)
}

// unmountNative detaches the RAM disk mounted at path.
func unmountNative(path string) error {
	cmd := exec.Command("diskutil", "unmount", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("diskutil unmount failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unmountNativeSudo is not needed on macOS: diskutil(1) does not require
// elevated privileges for RAM disks, so it reuses the native path.
func unmountNativeSudo(path string) error {
	return unmountNative(path)
}

// isMountPoint reports whether path is listed as mounted by mount(8).
func isMountPoint(path string) bool {
	out, err := exec.Command("mount").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, " on "+path+" ") || strings.Contains(line, " on "+path+" (") {
			return true
		}
	}
	return false
}
