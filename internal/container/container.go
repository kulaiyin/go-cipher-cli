// Package container mirrors packages/web/src/utils/data-encryption.ts: the binary
// container that wraps an AES-GCM ciphertext together with the salt_seed needed
// to re-derive the key.
//
// Layout (little-endian):
//
//	offset 0   4   version       (uint32 LE; encrypt path writes 10000)
//	offset 4   4   reserved      (uint32 LE; 0)
//	offset 8   64  salt_seed     (raw bytes; 128-hex when rendered)
//	offset 72  4   length        (uint32 LE; ciphertext byte length)
//	offset 76  N   ciphertext    (iv ‖ ct ‖ tag)
package container

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
)

// uuidHintRe mirrors the JS regex /密钥UUID: ([a-f0-9*]+)/i. The (?i) flag makes both the
// literal prefix and the [a-f] range case-insensitive (so [A-F] also matches), matching the
// reference's /i behaviour. The capture keeps the original case for a case-sensitive compare.
var uuidHintRe = regexp.MustCompile(`(?i)密钥UUID: ([a-f0-9*]+)`)

// ValidateHintAndKeysUuidMatch mirrors data-encryption.ts:validateHintAndKeysUuidMatch.
//   - if encryptedHint has no UUID match -> true
//   - else if metaHint has no UUID match -> false
//   - else return whether the two captured UUIDs are byte-for-byte equal (case-sensitive)
func ValidateHintAndKeysUuidMatch(encryptedHint, metaHint string) bool {
	encMatch := uuidHintRe.FindStringSubmatch(encryptedHint)
	if encMatch == nil {
		return true
	}
	metaMatch := uuidHintRe.FindStringSubmatch(metaHint)
	if metaMatch == nil {
		return false
	}
	return trimSpace(encMatch[1]) == trimSpace(metaMatch[1])
}

// trimSpace mirrors JS String.prototype.trim (ASCII whitespace, which is what these hints use).
func trimSpace(s string) string {
	start := 0
	for start < len(s) && isASCIISpace(s[start]) {
		start++
	}
	end := len(s)
	for end > start && isASCIISpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

const (
	headerSize  = 76 // version(4)+reserved(4)+salt_seed(64)+length(4)
	saltSeedLen = 64 // raw bytes
)

// Decrypted holds the parsed container fields.
type Decrypted struct {
	Version       uint32
	Reserved      uint32
	SaltSeed      string // 128-hex
	DataLength    uint32
	EncryptedData []byte
}

// AssembleDownloadData builds the binary container. saltSeedHex must decode to
// exactly 64 bytes (128 hex chars); the bytes are stored raw at offset 8.
func AssembleDownloadData(version, reserved uint32, saltSeedHex string, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return nil, errors.New("container: empty encrypted data")
	}
	saltBytes, err := hex.DecodeString(saltSeedHex)
	if err != nil {
		return nil, fmt.Errorf("container: salt_seed hex: %w", err)
	}
	if len(saltBytes) > saltSeedLen {
		// mirror the frontend: it writes min(len, 64) bytes, padding with zero.
		saltBytes = saltBytes[:saltSeedLen]
	}

	total := headerSize + len(encryptedData)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], version)
	binary.LittleEndian.PutUint32(buf[4:8], reserved)
	// write salt bytes (pad remaining with 0, mirroring `salt_buffer[i] || 0`)
	copy(buf[8:8+saltSeedLen], saltBytes)
	binary.LittleEndian.PutUint32(buf[72:76], uint32(len(encryptedData)))
	copy(buf[headerSize:], encryptedData)
	return buf, nil
}

// ExtractDecryptedData parses a container built by AssembleDownloadData.
func ExtractDecryptedData(data []byte) (*Decrypted, error) {
	if len(data) < headerSize {
		return nil, errors.New("container: data too short (<76 bytes)")
	}
	version := binary.LittleEndian.Uint32(data[0:4])
	reserved := binary.LittleEndian.Uint32(data[4:8])
	saltSeed := hex.EncodeToString(data[8 : 8+saltSeedLen])
	dataLength := binary.LittleEndian.Uint32(data[72:76])
	if headerSize+int(dataLength) > len(data) {
		return nil, errors.New("container: stated length exceeds available data")
	}
	return &Decrypted{
		Version:       version,
		Reserved:      reserved,
		SaltSeed:      saltSeed,
		DataLength:    dataLength,
		EncryptedData: data[headerSize:],
	}, nil
}

// ExtractSaltFromEncryptedData reads the 64 salt_seed bytes at offset 8–72 and
// returns them as a 128-char hex string.
func ExtractSaltFromEncryptedData(data []byte) string {
	if len(data) < 72 {
		return ""
	}
	return hex.EncodeToString(data[8 : 8+saltSeedLen])
}
