package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivilegeRequiredError_ErrorsAs(t *testing.T) {
	// DoUpdate returns *PrivilegeRequiredError, and cmd/ wraps it via
	// fmt.Errorf("%w"). errors.As must still unwrap to our concrete type so the
	// caller can recover StagingPath/ExecPath and resume with InstallWithSudo.
	orig := &PrivilegeRequiredError{
		StagingPath: "/tmp/staging/go-cipher-cli.new",
		ExecPath:    "/usr/bin/go-cipher-cli",
	}
	wrapped := wrap(orig) // one %w layer, like cmd/update.go does

	var got *PrivilegeRequiredError
	if !errors.As(wrapped, &got) {
		t.Fatalf("errors.As failed to unwrap *PrivilegeRequiredError")
	}
	if got.StagingPath != orig.StagingPath || got.ExecPath != orig.ExecPath {
		t.Fatalf("recovered fields mismatch: got %+v, want %+v", got, orig)
	}
	if !strings.Contains(got.Error(), orig.ExecPath) {
		t.Fatalf("Error() = %q, want it to contain %q", got.Error(), orig.ExecPath)
	}
}

// wrap mirrors fmt.Errorf("%s: %w", msg, err) used by the cmd layer.
func wrap(err error) error { return errWrap{"update failed", err} }

type errWrap struct {
	msg string
	err error
}

func (e errWrap) Error() string { return e.msg + ": " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

func TestFindChecksum(t *testing.T) {
	const checksums = "abc123  go-cipher-cli_0.4.8_linux_amd64.tar.gz\n" +
		"def456  go-cipher-cli_0.4.8_darwin_arm64.tar.gz\n"

	tests := []struct {
		name  string
		input string
		asset string
		want  string
	}{
		{"double-space (goreleaser convention)", checksums, "go-cipher-cli_0.4.8_linux_amd64.tar.gz", "abc123"},
		{"single-space variant", "abc123 go-cipher-cli_x.tar.gz", "go-cipher-cli_x.tar.gz", "abc123"},
		{"no match", checksums, "missing.tar.gz", ""},
		{"empty input", "", "anything.tar.gz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findChecksum(tt.input, tt.asset); got != tt.want {
				t.Fatalf("findChecksum() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractBinary(t *testing.T) {
	const content = "fake-binary-bytes"
	binaryName := "go-cipher-cli"

	// Build a tar.gz containing the binary in both layouts.
	for _, layout := range []struct {
		name    string
		archive string // path of the binary inside the archive
	}{
		{"unwrapped (root)", binaryName},
		{"wrapped (in dir)", "go-cipher-cli-0.4.8/" + binaryName},
	} {
		t.Run(layout.name, func(t *testing.T) {
			tarGzPath := makeTarGz(t, map[string]string{layout.archive: content})

			dest := filepath.Join(t.TempDir(), "out")
			if err := extractBinary(tarGzPath, dest); err != nil {
				t.Fatalf("extractBinary failed: %v", err)
			}
			got, err := os.ReadFile(dest)
			if err != nil {
				t.Fatalf("read extracted file: %v", err)
			}
			if string(got) != content {
				t.Fatalf("extracted content = %q, want %q", got, content)
			}
		})
	}

	t.Run("binary missing", func(t *testing.T) {
		tarGzPath := makeTarGz(t, map[string]string{"other-file": "x"})
		dest := filepath.Join(t.TempDir(), "out")
		err := extractBinary(tarGzPath, dest)
		if err == nil {
			t.Fatal("expected error for missing binary, got nil")
		}
	})
}

// makeTarGz builds an in-memory tar.gz from a map of path->content and writes
// it to a temp file, returning the path.
func makeTarGz(t *testing.T, files map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write tar body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write tar.gz file: %v", err)
	}
	return path
}

// TestVerifyChecksum_Archive verifies that verifyChecksum checks the downloaded
// archive (tar.gz) itself, matching goreleaser's checksums.txt convention —
// NOT the extracted binary. This guards against the regression where the
// archive checksum was compared against the extracted-binary checksum.
func TestVerifyChecksum_Archive(t *testing.T) {
	// Build a real tar.gz archive and compute ITS checksum.
	tarGzPath := makeTarGz(t, map[string]string{"go-cipher-cli": "payload"})
	archiveBytes, err := os.ReadFile(tarGzPath)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	sum := sha256.Sum256(archiveBytes)
	archiveSHA := hex.EncodeToString(sum[:])

	// checksums.txt records the archive's checksum (goreleaser convention).
	assetName := "go-cipher-cli_9.9.9_linux_amd64.tar.gz"
	checksums := archiveSHA + "  " + assetName + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, checksums)
	}))
	defer srv.Close()

	// Verifying the archive path must pass.
	if err := verifyChecksum(tarGzPath, srv.URL, "linux", "amd64", "9.9.9"); err != nil {
		t.Fatalf("verifyChecksum(archive) should pass: %v", err)
	}

	// Sanity: a wrong checksum in checksums.txt must fail.
	bad := strings.Repeat("0", 64) + "  " + assetName + "\n"
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, bad)
	}))
	defer srv2.Close()
	if err := verifyChecksum(tarGzPath, srv2.URL, "linux", "amd64", "9.9.9"); err == nil {
		t.Fatal("verifyChecksum should fail on mismatched checksum")
	}
}
