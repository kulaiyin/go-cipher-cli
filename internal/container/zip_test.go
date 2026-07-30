package container

import (
	"archive/zip"
	"bytes"
	"testing"
)

type testEntry struct {
	name string
	data []byte
}

// zipNamed builds a valid ZIP with arbitrary entry names (for missing-core tests).
func zipNamed(items []testEntry) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, it := range items {
		fw, _ := w.Create(it.name)
		_, _ = fw.Write(it.data)
	}
	_ = w.Close()
	return buf.Bytes()
}

func TestCompressDecompressBundle_RoundTrip(t *testing.T) {
	bin := []byte("BINARY-CONTAINER-BYTES-1234567890")
	meta := []byte(`{"version":10000,"sha256":"abc","hint":"h","selectedHints":["a"]}`)
	zipData, err := CompressBundle(BundleEntries{Bin: bin, Meta: meta})
	if err != nil {
		t.Fatalf("CompressBundle: %v", err)
	}
	if !IsBundleZip(zipData) {
		t.Fatal("IsBundleZip should recognize the output")
	}
	out, err := DecompressBundle(zipData)
	if err != nil {
		t.Fatalf("DecompressBundle: %v", err)
	}
	if !bytes.Equal(out.Bin, bin) {
		t.Errorf("bin mismatch:\n got %q\nwant %q", out.Bin, bin)
	}
	if !bytes.Equal(out.Meta, meta) {
		t.Errorf("meta mismatch:\n got %q\nwant %q", out.Meta, meta)
	}
}

func TestCompressBundle_EmptyEntries(t *testing.T) {
	if _, err := CompressBundle(BundleEntries{Bin: nil, Meta: []byte("x")}); err == nil {
		t.Fatal("expected error for empty bin")
	}
}

func TestDecompressBundle_NotZip(t *testing.T) {
	if _, err := DecompressBundle([]byte("this is not a zip")); err == nil {
		t.Fatal("expected error for non-zip input")
	}
}

func TestDecompressBundle_MissingCore(t *testing.T) {
	// Valid zip but missing encrypted-data.bin -> missing-core error.
	wrongZip := zipNamed([]testEntry{{"wrong.bin", []byte("b")}, {metaEntryName, []byte("m")}})
	if _, err := DecompressBundle(wrongZip); err == nil {
		t.Fatal("expected missing-core error when encrypted-data.bin absent")
	}
	// Valid zip but missing meta-data.json -> missing-core error.
	wrongZip2 := zipNamed([]testEntry{{binEntryName, []byte("b")}, {"other.json", []byte("m")}})
	if _, err := DecompressBundle(wrongZip2); err == nil {
		t.Fatal("expected missing-core error when meta-data.json absent")
	}
}
