package container

// Package container: ZIP bundle support for the data-encryption product.
//
// The web tool ships the encrypted data as a ZIP containing two entries:
//
//	encrypted-<ts>.zip
//	├── encrypted-data.bin   (binary container: 76B header + AES-GCM ciphertext)
//	└── meta-data.json       (MetaData JSON, incl. metaHash / integrityHash)
//
// Compression uses DEFLATE level 6 on the web side (JSZip). For CLI→web interop
// the CLI only needs to emit a *valid* standard ZIP; the decrypt side verifies
// entry contents (SHA256) after decompression, not the byte-level ZIP encoding.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"

	"go-cipher-cli/internal/i18n"
)

const (
	binEntryName  = "encrypted-data.bin"
	metaEntryName = "meta-data.json"
)

// BundleEntries is the pair of files carried inside the encryption ZIP.
type BundleEntries struct {
	Bin  []byte // encrypted-data.bin (the binary container)
	Meta []byte // meta-data.json (MetaData JSON)
}

// CompressBundle zips the two entries (DEFLATE) into a single .zip, matching the
// web tool's compressFiles output layout (encrypted-data.bin + meta-data.json).
func CompressBundle(b BundleEntries) ([]byte, error) {
	if len(b.Bin) == 0 || len(b.Meta) == 0 {
		return nil, fmt.Errorf("%s", i18n.T("zip.error.empty_entries"))
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, item := range []struct {
		name string
		data []byte
	}{
		{binEntryName, b.Bin},
		{metaEntryName, b.Meta},
	} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: item.name, Method: zip.Deflate})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("zip.error.write_entry"), err)
		}
		if _, err := fw.Write(item.data); err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("zip.error.write_entry"), err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("zip.error.close"), err)
	}
	return buf.Bytes(), nil
}

// DecompressBundle reads a ZIP and extracts encrypted-data.bin + meta-data.json.
// It validates that both core entries exist (web tool's "missing core component" rule).
func DecompressBundle(zipData []byte) (*BundleEntries, error) {
	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("zip.error.not_zip"), err)
	}
	var b BundleEntries
	var haveBin, haveMeta bool
	for _, f := range r.File {
		switch f.Name {
		case binEntryName:
			b.Bin, err = readZipEntry(f)
			if err != nil {
				return nil, err
			}
			haveBin = true
		case metaEntryName:
			b.Meta, err = readZipEntry(f)
			if err != nil {
				return nil, err
			}
			haveMeta = true
		}
	}
	if !haveBin || !haveMeta {
		return nil, fmt.Errorf("%s", i18n.T("zip.error.missing_core"))
	}
	return &b, nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("%s (%s): %w", i18n.T("zip.error.read_entry"), f.Name, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("%s (%s): %w", i18n.T("zip.error.read_entry"), f.Name, err)
	}
	return data, nil
}

// IsBundleZip is a cheap check whether a byte slice is a ZIP (PK\x03\x04 magic).
func IsBundleZip(data []byte) bool {
	return len(data) > 4 && data[0] == 'P' && data[1] == 'K' && (data[2] == 3 || data[2] == 5 || data[2] == 7) && data[3] == 4
}
