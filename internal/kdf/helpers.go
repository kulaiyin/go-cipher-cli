package kdf

import (
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func nowMs() int64 { return time.Now().UnixMilli() }

func elapsedMs(start int64) int64 { return time.Now().UnixMilli() - start }

func errMsg(err error, def string) string {
	if err == nil {
		return def
	}
	return err.Error()
}

// hkdfWithSalt runs a full HKDF-SHA3-512 (Extract+Expand) with the given salt.
// Mirrors SafetyUtility.hkdf (which always uses @noble/hashes full hkdf).
func hkdfWithSalt(ikm, salt, info []byte, length int) []byte {
	r := hkdf.New(sha3.New512, ikm, salt, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(fmt.Sprintf("kdf: hkdf read: %v", err))
	}
	return out
}
