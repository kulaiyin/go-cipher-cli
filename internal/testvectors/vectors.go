// Package testvectors loads the golden test vectors used to verify the crypto
// implementation. Tests under other internal packages consume them.
package testvectors

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed vectors.json
var vectorsJSON []byte

// Vectors is the parsed golden-vector set.
type Vectors struct {
	HKDFExpand []struct {
		Name         string `json:"name"`
		PRK          string `json:"prk"`
		Info         string `json:"info"`
		InfoBytesHex string `json:"infoBytesHex"`
		Length       int    `json:"length"`
		Out          string `json:"out"`
	} `json:"hkdfExpand"`

	HMACSHA3512 []struct {
		Data string `json:"data"`
		Key  string `json:"key"`
		Out  string `json:"out"`
	} `json:"hmacSha3_512"`

	Argon2id []struct {
		Password    string `json:"password"`
		SaltHex     string `json:"saltHex"`
		Iterations  int    `json:"iterations"`
		MemorySize  int    `json:"memorySize"`
		Parallelism int    `json:"parallelism"`
		HashLength  int    `json:"hashLength"`
		OutHex      string `json:"outHex"`
	} `json:"argon2id"`

	Argon2id64mb struct {
		Password    string `json:"password"`
		SaltHex     string `json:"saltHex"`
		Iterations  int    `json:"iterations"`
		MemorySize  int    `json:"memorySize"`
		Parallelism int    `json:"parallelism"`
		HashLength  int    `json:"hashLength"`
		OutHex      string `json:"outHex"`
	} `json:"argon2id64mb"`

	GenerateAesGcmKey struct {
		Salt               string   `json:"salt"`
		Passwords          []string `json:"passwords"`
		SaltText           string   `json:"salt_text"`
		SaltPRK            string   `json:"salt_prk"`
		S1                 string   `json:"s1"`
		S2                 string   `json:"s2"`
		S3                 string   `json:"s3"`
		Sdata              string   `json:"sdata"`
		ProcessedPasswords []string `json:"processedPasswords"`
		Argon2RawHex       []string `json:"argon2RawHex"`
		UsrStrongKey       string   `json:"usr_strong_key"`
		PRKDEK             string   `json:"prk_dek"`
		AesDEK             string   `json:"aes_dek"`
	} `json:"generateAesGcmKey"`

	GcmEncryptFixedIV struct {
		IV           string `json:"iv"`
		Plaintext    string `json:"plaintext"`
		PlaintextHex string `json:"plaintextHex"`
		AesDEKHex    string `json:"aes_dek_hex"`
		SdataHex     string `json:"sdata_hex"`
		IVUsed       string `json:"iv_used"`
		DataPRK      string `json:"data_prk"`
		Result       string `json:"result"`
	} `json:"gcmEncryptFixedIV"`

	FusePasswords struct {
		Basic    []FusePasswordCase `json:"basic"`
		Extended []FusePasswordCase `json:"extended"`
	} `json:"fusePasswords"`

	NormalizePassword []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"normalizePassword"`

	SHA256 []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"sha256"`

	ValidatePasswordStrength []struct {
		In       string   `json:"in"`
		Score    int      `json:"score"`
		Feedback []string `json:"feedback"`
	} `json:"validatePasswordStrength"`

	ValidateHintAndKeysUuidMatch []struct {
		Encrypted string `json:"encrypted"`
		Meta      string `json:"meta"`
		Out       bool   `json:"out"`
	} `json:"validateHintAndKeysUuidMatch"`

	ValidateKeyRecovery []struct {
		Key   string   `json:"key"`
		Uuids []string `json:"uuids"`
		Out   bool     `json:"out"`
	} `json:"validateKeyRecovery"`

	AssemblePackageKey []struct {
		Name              string   `json:"name"`
		Keys              []string `json:"keys"`
		AssembledPassword string   `json:"assembledPassword"`
		Salt              string   `json:"salt"`
		Iterations        int      `json:"iterations"`
		MemorySize        int      `json:"memorySize"`
		Parallelism       int      `json:"parallelism"`
		HashLength        int      `json:"hashLength"`
		Info              string   `json:"info"`
		OutHex            string   `json:"outHex"`
	} `json:"assemblePackageKey"`

	MetaDataDigest []struct {
		Name          string   `json:"name"`
		Version       uint32   `json:"version"`
		Salt          string   `json:"salt"`
		CreatedAt     int64    `json:"createdAt"`
		SelectedHints []string `json:"selectedHints"`
		SHA256        string   `json:"sha256"`
		Payload       string   `json:"payload"`
		MetaHash      string   `json:"metaHash"`
		IntegrityHash string   `json:"integrityHash"`
	} `json:"metaDataDigest"`
}

// FusePasswordCase is one fusePasswords golden case.
type FusePasswordCase struct {
	Salt      string   `json:"salt"`
	Passwords []string `json:"passwords"`
	Out       string   `json:"out"`
}

var loaded *Vectors

// Load parses the embedded vectors.json exactly once and returns the cached set.
func Load() (*Vectors, error) {
	if loaded != nil {
		return loaded, nil
	}
	var v Vectors
	if err := json.Unmarshal(vectorsJSON, &v); err != nil {
		return nil, fmt.Errorf("testvectors: %w", err)
	}
	loaded = &v
	return loaded, nil
}

// MustLoad is Load but panics on error (test-only convenience).
func MustLoad() *Vectors {
	v, err := Load()
	if err != nil {
		panic(err)
	}
	return v
}
