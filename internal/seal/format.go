// Package seal implements the secret-seal scheme: encrypt a final password P
// with age + AES-256-GCM, protect the age private key with Shamir secret sharing
// across 5 shares, and provide a muscle-memory password fallback for K1 recovery.
//
// File formats (all JSON, then Base64-encoded on disk):
//
//	encrypt-d.dat  → EncryptedData  — age(P) then AES-256-GCM(KD)
//	encrypt-k.dat  → EncryptedK1    — AES-256-GCM(S1, K1) with salt S
//	share-N.dat    → EncryptedShare — AES-256-GCM(K_i, shamir_share_i)
package seal

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
)

// --- on-disk formats (JSON, stored as Base64) ---

// EncryptedData holds the doubly-encrypted secret P.
// P is first encrypted with age (public key), then with AES-256-GCM(key=KD).
type EncryptedData struct {
	AgeEncrypted []byte `json:"age_encrypted"` // age-encrypted P
	AESIV        []byte `json:"aes_iv"`        // 12-byte IV for AES-256-GCM
	AESCT        []byte `json:"aes_ct"`        // AES-256-GCM ciphertext
}

// EncryptedK1 holds the fallback-encrypted Diceware passphrase K1.
// K1 is encrypted with AES-256-GCM using key S1 (derived from muscle password).
// The salt S used for K1→KH derivation is stored here so recovery can re-derive.
// Hint is an optional plaintext memory aid for recalling K1.
type EncryptedK1 struct {
	Hint  string `json:"hint"`   // optional plaintext hint to help recall K1
	SaltS []byte `json:"salt_s"` // 16-byte random salt for K1→KH argon2id
	AESIV []byte `json:"aes_iv"` // 12-byte IV
	AESCT []byte `json:"aes_ct"` // AES-256-GCM(S1, K1)
}

// EncryptedShare holds one Shamir share encrypted with a share-specific key.
type EncryptedShare struct {
	ShareIndex int    `json:"share_index"` // 1-based share index
	AESIV      []byte `json:"aes_iv"`      // 12-byte IV
	AESCT      []byte `json:"aes_ct"`      // AES-256-GCM(K_i, share_i)
}

// --- Public helpers ---

// ReadEncryptedK1 reads encrypt-k.dat into the given struct.
func ReadEncryptedK1(vaultDir string, ek *EncryptedK1) error {
	return readJSONBase64(filepath.Join(vaultDir, "encrypt-k.dat"), ek)
}

// --- IO helpers ---

func writeJSONBase64(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return os.WriteFile(path, []byte(encoded), 0600)
}

func readJSONBase64(path string, v interface{}) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
