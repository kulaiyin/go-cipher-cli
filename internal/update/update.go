// Package update provides self-update functionality for go-cipher-cli.
//
// It queries the GitHub Releases API for the latest version, downloads the
// matching tar.gz asset, verifies its SHA256 checksum, and replaces the
// current binary atomically. When the binary is installed in a root-owned
// directory (e.g. /usr/bin), it falls back to sudo mv for the final step.
package update

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ReleaseInfo holds the latest release metadata fetched from GitHub.
type ReleaseInfo struct {
	Version     string // semantic version without "v" prefix (e.g. "0.4.2")
	TagName     string // raw tag name (e.g. "v0.4.2")
	AssetURL    string // download URL for the matching tar.gz
	ChecksumURL string // download URL for checksums.txt
}

// GitHubRelease represents the subset of GitHub Releases API response we need.
type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

const githubAPI = "https://api.github.com/repos/kulaiyin/go-cipher-cli/releases/latest"

// CheckLatest fetches the latest release from GitHub and returns a ReleaseInfo
// if there is a newer version. Returns nil, nil when already up-to-date.
func CheckLatest(currentVersion, goos, goarch string) (*ReleaseInfo, error) {
	latest, err := fetchRelease()
	if err != nil {
		return nil, err
	}

	latestVer := strings.TrimPrefix(latest.TagName, "v")
	curVer := strings.TrimPrefix(currentVersion, "v")

	if !isNewer(latestVer, curVer) {
		return nil, nil // already up-to-date
	}

	assetName := fmt.Sprintf("go-cipher-cli_%s_%s_%s.tar.gz", latestVer, goos, goarch)
	checksumName := "checksums.txt"

	info := &ReleaseInfo{
		Version: latestVer,
		TagName: latest.TagName,
	}

	for _, a := range latest.Assets {
		switch a.Name {
		case assetName:
			info.AssetURL = a.BrowserDownloadURL
		case checksumName:
			info.ChecksumURL = a.BrowserDownloadURL
		}
	}

	if info.AssetURL == "" {
		return nil, fmt.Errorf("no matching asset found for %s/%s (%s)", goos, goarch, assetName)
	}

	return info, nil
}

// DoUpdate downloads, extracts, verifies, and installs the update.
func DoUpdate(info *ReleaseInfo, goos, goarch string) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find current executable: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve executable symlink: %w", err)
	}

	stagingDir, err := os.MkdirTemp("", "go-cipher-cli-update-*")
	if err != nil {
		return fmt.Errorf("cannot create temp directory: %w", err)
	}
	// NOTE: stagingDir is removed manually on each return path rather than via
	// defer. When privilege is required, the staged binary must survive so the
	// caller can run InstallWithSudo after the user grants permission.
	stagingPath := filepath.Join(stagingDir, "go-cipher-cli.new")

	// 1. Download tar.gz
	tarGzPath := stagingPath + ".tar.gz"
	defer os.Remove(tarGzPath)

	if err := download(info.AssetURL, tarGzPath); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("download failed: %w", err)
	}

	// 2. Verify checksum of the downloaded tar.gz against checksums.txt.
	// goreleaser's checksums.txt records the SHA256 of each archive (tar.gz/zip),
	// so we verify the archive before extracting — not the extracted binary.
	if info.ChecksumURL != "" {
		if err := verifyChecksum(tarGzPath, info.ChecksumURL, goos, goarch, info.Version); err != nil {
			os.RemoveAll(stagingDir)
			return fmt.Errorf("checksum verification failed: %w", err)
		}
	}

	// 3. Extract binary from tar.gz
	if err := extractBinary(tarGzPath, stagingPath); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("extract failed: %w", err)
	}

	// 4. Make executable
	if err := os.Chmod(stagingPath, 0o755); err != nil {
		os.RemoveAll(stagingDir)
		return fmt.Errorf("chmod failed: %w", err)
	}

	// 5. Replace current binary. If the install directory is not writable
	// (e.g. /usr/bin), return ErrPrivilegeRequired so the caller can ask the
	// user for elevation and resume via InstallWithSudo. The staged binary is
	// intentionally left in place for that resume.
	if err := os.Rename(stagingPath, execPath); err != nil {
		if os.IsPermission(err) {
			return &PrivilegeRequiredError{StagingPath: stagingPath, ExecPath: execPath}
		}
		os.RemoveAll(stagingDir)
		return fmt.Errorf("replace failed: %w", err)
	}

	// Rename succeeded; nothing left to clean (stagingPath moved into place).
	os.RemoveAll(stagingDir)
	return nil
}

// PrivilegeRequiredError is returned by DoUpdate when the install directory is
// not writable by the current user. The caller should prompt the user for
// consent and, if granted, call InstallWithSudo with the paths carried here.
type PrivilegeRequiredError struct {
	StagingPath string // path to the downloaded/verified new binary
	ExecPath    string // path of the binary to replace
}

func (e *PrivilegeRequiredError) Error() string {
	return fmt.Sprintf("permission denied writing to %s; elevation required", e.ExecPath)
}

// InstallWithSudo replaces execPath with stagingPath using sudo mv, connecting
// stdin/stdout/stderr so the user can enter their sudo password interactively.
// The caller is responsible for obtaining user consent before calling this.
func InstallWithSudo(stagingPath, execPath string) error {
	cmd := exec.Command("sudo", "mv", stagingPath, execPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Leave stagingPath in place so the user can retry or move it manually.
		return fmt.Errorf("sudo failed: %w\nRun manually:\n  sudo mv %s %s",
			err, stagingPath, execPath)
	}
	return nil
}

// isNewer returns true if a > b using semver-like comparison.
func isNewer(a, b string) bool {
	// If versions are identical, not newer.
	// If either is empty/unparseable, return false.
	ap := splitVersion(a)
	bp := splitVersion(b)
	if len(ap) == 0 || len(bp) == 0 {
		return false
	}
	for i := 0; i < len(ap) || i < len(bp); i++ {
		va := 0
		if i < len(ap) {
			va = ap[i]
		}
		vb := 0
		if i < len(bp) {
			vb = bp[i]
		}
		if va > vb {
			return true
		}
		if va < vb {
			return false
		}
	}
	return false
}

func splitVersion(v string) []int {
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			} else {
				break // stop at first non-digit (e.g. "-rc1")
			}
		}
		nums = append(nums, n)
	}
	return nums
}

// fetchRelease queries the GitHub Releases API and returns the latest release.
func fetchRelease() (*githubRelease, error) {
	req, err := http.NewRequest("GET", githubAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "go-cipher-cli")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("GitHub API returned empty tag_name")
	}
	return &rel, nil
}

// download fetches a URL and writes the body to destPath.
func download(url, destPath string) error {
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(f, resp.Body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// extractBinary extracts the go-cipher-cli binary from a tar.gz archive.
// It handles both wrapped (directory/binary) and unwrapped (binary only) layouts.
func extractBinary(tarGzPath, destPath string) error {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	binaryName := "go-cipher-cli"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Match the binary: either at root or inside a wrapping directory.
		name := filepath.Base(hdr.Name)
		if name != binaryName {
			continue
		}
		// Skip directories (unlikely but defensive).
		if hdr.Typeflag == tar.TypeDir {
			continue
		}

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, tr)
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		return err
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

// verifyChecksum downloads checksums.txt, finds the line for our archive
// (tar.gz), and verifies the SHA256 of archivePath matches. The caller must
// pass the downloaded archive path, since goreleaser records archive checksums.
func verifyChecksum(archivePath, checksumURL, goos, goarch, version string) error {
	checksums, err := downloadString(checksumURL)
	if err != nil {
		return fmt.Errorf("cannot download checksums: %w", err)
	}

	assetName := fmt.Sprintf("go-cipher-cli_%s_%s_%s.tar.gz", version, goos, goarch)
	expected := findChecksum(checksums, assetName)
	if expected == "" {
		return fmt.Errorf("checksum entry not found for %s", assetName)
	}

	actual, err := sha256File(archivePath)
	if err != nil {
		return err
	}

	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("checksum mismatch:\n  expected: %s\n  actual:   %s", expected, actual)
	}
	return nil
}

func downloadString(url string) (string, error) {
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var sb strings.Builder
	_, err = io.Copy(&sb, resp.Body)
	return sb.String(), err
}

// findChecksum looks for a line in checksums.txt matching the given asset name.
// Format: <sha256>  <filename>
func findChecksum(checksums, assetName string) string {
	for _, line := range strings.Split(checksums, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Split into checksum and filename (2 spaces is goreleaser convention).
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			// Also try single space.
			parts = strings.SplitN(line, " ", 2)
		}
		if len(parts) == 2 && parts[1] == assetName {
			return parts[0]
		}
	}
	return ""
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
