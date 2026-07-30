package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/age"
	shamir "github.com/hashicorp/vault/shamir"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/safety"
)

const (
	// NumShares is the total number of Shamir shares.
	NumShares = 5
	// Threshold is the minimum number of shares needed to reconstruct.
	Threshold = 3

	// argon2 parameters for K1 → KH derivation.
	argon2MemoryKiB  = 64 * 1024 // 64 MiB
	argon2Iterations = 3
	argon2Parallel   = 1
	khLength         = 32 // 256 bits

	// argon2 parameters for muscle-password → S1 derivation.
	s1Length = 32 // 256 bits

	// saltSLength is the random salt for K1→KH derivation.
	saltSLength = 16
)

// Domain separation info strings for HKDF (SHA-256).
var (
	infoSealKeyT  = []byte("seal-key-t")
	infoSealKeyKT = []byte("seal-key-kt")
	infoSealKeyKD = []byte("seal-key-kd")
	infoShareKey  = []byte("share-key-v1")
)

// --- public API ---

// Seal performs the full seal operation:
//
//	K1 → Argon2id(salt=S) → KH
//	KH → HKDF → T, KT, KD
//	P  → age(E_pub) → AES-256-GCM(KD) → encrypt-d.dat
//	E_priv → T_enc → AES-256-GCM(KT) → Shamir(3/5) → K_i encrypt shares
//	K1 → AES-256-GCM(S1) → encrypt-k.dat
func Seal(k1, musclePassword, p, hint, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.create_dir"), err)
	}

	// 1. Generate age key pair.
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.generate_age_key"), err)
	}
	agePub := ageID.Recipient()

	// 2. Generate random salt S for K1→KH derivation.
	saltS := safety.GenerateRandomBytes(saltSLength)

	// 3. Derive KH from K1 with salt S.
	kh, err := deriveKH(k1, saltS)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.derive_kh"), err)
	}
	defer wipe(kh)

	// 4. Derive T, KT, KD from KH via HKDF.
	t, kt, kd := deriveSubKeys(kh)
	defer wipe(t)
	defer wipe(kt)
	defer wipe(kd)

	// 5. Encrypt P with age, then AES-256-GCM(KD) → encrypt-d.dat.
	ageEncrypted, err := ageEncrypt(agePub, []byte(p))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.age_encrypt"), err)
	}
	encData, err := aesGCMEncrypt(kd, ageEncrypted)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.aes_encrypt"), err)
	}
	ed := &EncryptedData{
		AgeEncrypted: ageEncrypted,
		AESIV:        encData.iv,
		AESCT:        encData.ct,
	}
	if err := writeJSONBase64(filepath.Join(outputDir, "encrypt-d.dat"), ed); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.write_file"), err)
	}

	// 6. Export age private key, encrypt with T then AES-256-GCM(KT), Shamir split.
	agePriv := ageID.String()
	tEncrypted, err := aesGCMEncrypt(t, []byte(agePriv))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.seal_age_priv"), err)
	}
	// Second layer: AES-256-GCM(KT).
	fullPayload := append(tEncrypted.iv, tEncrypted.ct...)
	ktEncrypted, err := aesGCMEncrypt(kt, fullPayload)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.aes_encrypt"), err)
	}
	toSplit := append(ktEncrypted.iv, ktEncrypted.ct...)

	shares, err := shamir.Split(toSplit, NumShares, Threshold)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.shamir_split"), err)
	}

	// 7. Encrypt each share with K_i and write to shares/ dir.
	sharesDir := filepath.Join(outputDir, "shares")
	if err := os.MkdirAll(sharesDir, 0700); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.create_dir"), err)
	}
	for i, share := range shares {
		ki := deriveShareKey([]byte(k1), i+1)
		encShare, err := aesGCMEncrypt(ki, share)
		wipe(ki)
		if err != nil {
			return fmt.Errorf("%s", i18n.TWithData("seal.error.encrypt_share", map[string]interface{}{"Index": i + 1, "Err": err}))
		}
		es := &EncryptedShare{
			ShareIndex: i + 1,
			AESIV:      encShare.iv,
			AESCT:      encShare.ct,
		}
		if err := writeJSONBase64(filepath.Join(sharesDir, "share-"+strconv.Itoa(i+1)+".dat"), es); err != nil {
			return fmt.Errorf("%s", i18n.TWithData("seal.error.write_file", map[string]interface{}{"Err": err}))
		}
	}

	// 8. Derive S1 from muscle password and encrypt K1 → encrypt-k.dat.
	s1, err := deriveS1(musclePassword)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.derive_s1"), err)
	}
	defer wipe(s1)
	encK1, err := aesGCMEncrypt(s1, []byte(k1))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.aes_encrypt"), err)
	}
	ek := &EncryptedK1{
		Hint:  hint,
		SaltS: saltS,
		AESIV: encK1.iv,
		AESCT: encK1.ct,
	}
	if err := writeJSONBase64(filepath.Join(outputDir, "encrypt-k.dat"), ek); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("seal.error.write_file"), err)
	}

	return nil
}

// UnsealPrimary recovers P using K1 (the Diceware passphrase) and the output dir.
func UnsealPrimary(k1, inputDir string) (string, error) {
	// 1. Read encrypt-k.dat to get salt S.
	ek := &EncryptedK1{}
	if err := readJSONBase64(filepath.Join(inputDir, "encrypt-k.dat"), ek); err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.read_file"), err)
	}

	// 2. Derive KH, T, KT, KD from K1.
	kh, err := deriveKH(k1, ek.SaltS)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.derive_kh"), err)
	}
	defer wipe(kh)
	t, kt, kd := deriveSubKeys(kh)
	defer wipe(t)
	defer wipe(kt)
	defer wipe(kd)

	// 3. Reconstruct age private key from shares.
	agePriv, err := reconstructAgePriv(k1, t, kt, inputDir)
	if err != nil {
		return "", fmt.Errorf("%s", i18n.T("seal.error.reconstruct_age"))
	}

	// 4. Read and decrypt encrypt-d.dat.
	ed := &EncryptedData{}
	if err := readJSONBase64(filepath.Join(inputDir, "encrypt-d.dat"), ed); err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.read_file"), err)
	}
	ageEncrypted, err := aesGCMDecrypt(kd, ed.AESIV, ed.AESCT)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.aes_decrypt"), err)
	}

	p, err := ageDecrypt(agePriv, ageEncrypted)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.age_decrypt"), err)
	}
	return string(p), nil
}

// UnsealFallback recovers P using the muscle-memory password (forgot K1, but
// remember the muscle password). Reads encrypt-k.dat to get K1, then proceeds
// as the primary path.
func UnsealFallback(musclePassword, inputDir string) (string, error) {
	// 1. Read encrypt-k.dat.
	ek := &EncryptedK1{}
	if err := readJSONBase64(filepath.Join(inputDir, "encrypt-k.dat"), ek); err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.read_file"), err)
	}

	// 2. Derive S1 and decrypt K1.
	s1, err := deriveS1(musclePassword)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.derive_s1"), err)
	}
	defer wipe(s1)
	k1Bytes, err := aesGCMDecrypt(s1, ek.AESIV, ek.AESCT)
	if err != nil {
		return "", fmt.Errorf("%s", i18n.T("seal.error.wrong_muscle_password"))
	}
	k1 := string(k1Bytes)

	// 3. Continue with primary unseal.
	return UnsealPrimary(k1, inputDir)
}

// --- internal helpers ---

// deriveKH derives KH (256-bit) from K1 using argon2id with salt S.
func deriveKH(k1 string, saltS []byte) ([]byte, error) {
	res := kdf.Argon2(k1, kdf.Argon2Config{
		Salt:        saltS,
		Iterations:  argon2Iterations,
		MemorySize:  argon2MemoryKiB,
		Parallelism: argon2Parallel,
		HashLength:  khLength,
	})
	if !res.Success {
		return nil, errors.New(res.Error)
	}
	// res.Data is hex-encoded; decode to raw bytes.
	kh, err := safety.HexToBytes(res.Data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("seal.error.derive_kh"), err)
	}
	return kh, nil
}

// deriveSubKeys derives T, KT, KD from KH using HKDF-Expand (SHA-256).
func deriveSubKeys(kh []byte) (t, kt, kd []byte) {
	t = safety.HKDFExpandSHA256(kh, infoSealKeyT, 32)
	kt = safety.HKDFExpandSHA256(kh, infoSealKeyKT, 32)
	kd = safety.HKDFExpandSHA256(kh, infoSealKeyKD, 32)
	return
}

// deriveS1 derives S1 (256-bit) from the muscle-memory password using argon2id
// with a fixed embedded salt (the salt is NOT secret — it's domain separation).
func deriveS1(musclePassword string) ([]byte, error) {
	// Use a fixed domain-separation salt. This is not a secret —
	// the security of S1 rests entirely on the muscle password's entropy.
	domainSalt := []byte("go-cipher-cli-secret-seal-s1-v1")
	res := kdf.Argon2(musclePassword, kdf.Argon2Config{
		Salt:        domainSalt,
		Iterations:  argon2Iterations,
		MemorySize:  argon2MemoryKiB,
		Parallelism: argon2Parallel,
		HashLength:  s1Length,
	})
	if !res.Success {
		return nil, errors.New(res.Error)
	}
	return safety.HexToBytes(res.Data)
}

// deriveShareKey derives K_i for share index i (1-based) from K1.
// K_i = HKDF-Expand-SHA256(K1, info="share-key-v1|i")
func deriveShareKey(k1 []byte, index int) []byte {
	info := fmt.Sprintf("%s|%d", string(infoShareKey), index)
	return safety.HKDFExpandSHA256(k1, []byte(info), 32)
}

// --- AES-256-GCM helpers (plain, no extra derivation) ---

type gcmResult struct {
	iv []byte
	ct []byte
}

func aesGCMEncrypt(key, plaintext []byte) (gcmResult, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return gcmResult{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return gcmResult{}, err
	}
	iv := safety.GenerateRandomBytes(12)
	ct := gcm.Seal(nil, iv, plaintext, nil)
	return gcmResult{iv: iv, ct: ct}, nil
}

func aesGCMDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ciphertext, nil)
}

// --- age helpers ---

func ageEncrypt(recipient age.Recipient, plaintext []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ageDecrypt(identity string, ciphertext []byte) ([]byte, error) {
	ids, err := age.ParseIdentities(strings.NewReader(identity))
	// FIXME: import "strings" added manually
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, errors.New(i18n.T("seal.error.age_decrypt"))
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), ids[0])
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// reconstructAgePriv reads share files from inputDir/shares/, decrypts and
// reconstructs the age private key.
func reconstructAgePriv(k1 string, t, kt []byte, inputDir string) (string, error) {
	sharesDir := filepath.Join(inputDir, "shares")
	entries, err := os.ReadDir(sharesDir)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.read_shares_dir"), err)
	}

	var collected [][]byte
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "share-") {
			continue
		}
		es := &EncryptedShare{}
		if err := readJSONBase64(filepath.Join(sharesDir, entry.Name()), es); err != nil {
			continue // skip unreadable shares
		}
		ki := deriveShareKey([]byte(k1), es.ShareIndex)
		share, err := aesGCMDecrypt(ki, es.AESIV, es.AESCT)
		wipe(ki)
		if err != nil {
			continue // skip shares we can't decrypt (wrong K1?)
		}
		collected = append(collected, share)
		if len(collected) >= Threshold {
			break
		}
	}
	if len(collected) < Threshold {
		return "", fmt.Errorf("%s", i18n.TWithData("seal.error.insufficient_shares", map[string]interface{}{"Need": Threshold, "Got": len(collected)}))
	}

	combined, err := shamir.Combine(collected)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.shamir_combine"), err)
	}

	// combined = iv(12) + ct, encrypted with K_t first, then with kt.
	// Reverse: decrypt with kt to get (iv_T || ct_T), then decrypt with T to get age priv.
	if len(combined) < 12 {
		return "", errors.New(i18n.T("seal.error.data_too_short"))
	}
	ktIV := combined[:12]
	ktCT := combined[12:]
	innerPayload, err := aesGCMDecrypt(kt, ktIV, ktCT)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.aes_decrypt"), err)
	}
	if len(innerPayload) < 12 {
		return "", errors.New(i18n.T("seal.error.data_too_short"))
	}
	tIV := innerPayload[:12]
	tCT := innerPayload[12:]
	agePrivBytes, err := aesGCMDecrypt(t, tIV, tCT)
	if err != nil {
		return "", fmt.Errorf("%s: %w", i18n.T("seal.error.aes_decrypt"), err)
	}
	return string(agePrivBytes), nil
}

// wipe zeros a byte slice.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
