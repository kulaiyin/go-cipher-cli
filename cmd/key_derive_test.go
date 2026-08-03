package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"go-cipher-cli/internal/form"
	"go-cipher-cli/internal/kdf"
	"go-cipher-cli/internal/password"
	"go-cipher-cli/internal/validation"
)

// preGenerateSaltSeed must only fill a fresh salt in generate mode, and never
// overwrite an explicit --salt.
func TestPreGenerateSaltSeed(t *testing.T) {
	t.Run("generate fills fresh salt", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Mode.Value = "generate"
		preGenerateSaltSeed(p)
		if len(p.Salt.Value) != 128 {
			t.Fatalf("expected 128-hex salt, got %q (len %d)", p.Salt.Value, len(p.Salt.Value))
		}
	})

	t.Run("generate keeps explicit salt", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Mode.Value = "generate"
		p.Salt.Value = "ab12"
		preGenerateSaltSeed(p)
		if p.Salt.Value != "ab12" {
			t.Fatalf("explicit salt overwritten: %q", p.Salt.Value)
		}
	})

	t.Run("restore never generates a salt", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Mode.Value = "restore"
		preGenerateSaltSeed(p)
		if p.Salt.Value != "" {
			t.Fatalf("restore should not pre-generate a salt, got %q", p.Salt.Value)
		}
	})

	t.Run("empty mode leaves salt empty", func(t *testing.T) {
		p := &keyDeriveParams{}
		preGenerateSaltSeed(p)
		if p.Salt.Value != "" {
			t.Fatalf("empty mode should not pre-generate a salt, got %q", p.Salt.Value)
		}
	})
}

// TestInteractiveSaltAfterModePick mirrors the interactive flow: afterStandardize
// runs with an empty mode (so no salt), then the mode is picked and promptKeyDerive
// pre-generates the salt so the QnA password and the derivation share it.
func TestInteractiveSaltAfterModePick(t *testing.T) {
	p := &keyDeriveParams{}
	preGenerateSaltSeed(p)
	if p.Salt.Value != "" {
		t.Fatalf("afterStandardize must not pre-generate with empty mode, got %q", p.Salt.Value)
	}
	p.Mode.Value = "generate"
	preGenerateSaltSeed(p)
	if len(p.Salt.Value) != 128 {
		t.Fatalf("after mode pick expected 128-hex salt, got %q (len %d)", p.Salt.Value, len(p.Salt.Value))
	}
}

// finalAnswers must preserve the per-step order of form results.
func TestFinalAnswers(t *testing.T) {
	results := []form.Result{
		{Step: 1, ID: "Q01", Answer: "20240101"},
		{Step: 2, ID: "Q06", Answer: "shanghai"},
		{Step: 3, ID: "Q23", Answer: "@abc"},
	}
	want := []string{"20240101", "shanghai", "@abc"}
	if got := finalAnswers(results); !reflect.DeepEqual(got, want) {
		t.Fatalf("finalAnswers = %v, want %v", got, want)
	}
}

// resultIDs must preserve the per-step order of form results.
func TestResultIDs(t *testing.T) {
	results := []form.Result{
		{Step: 1, ID: "Q01", Answer: "20240101"},
		{Step: 2, ID: "Q06", Answer: "shanghai"},
		{Step: 3, ID: "Q23", Answer: "@abc"},
	}
	want := []string{"Q01", "Q06", "Q23"}
	if got := resultIDs(results); !reflect.DeepEqual(got, want) {
		t.Fatalf("resultIDs = %v, want %v", got, want)
	}
}

// TestBuildRestoreSteps verifies that stored question IDs are reconstructed
// from the pool one per step, and that an unknown ID errors early.
func TestBuildRestoreSteps(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test file")
	}
	root := filepath.Dir(filepath.Dir(file))
	prev := tuiDemoConfig
	tuiDemoConfig = filepath.Join(root, "configs/hint-word-pools_en.json")
	defer func() { tuiDemoConfig = prev }()

	steps, err := loadFormSteps(localizedConfigPath())
	if err != nil {
		t.Fatalf("load pool: %v", err)
	}
	base := []string{steps[0][0].ID, steps[1][1].ID, steps[2][2].ID}

	t.Run("reconstructs one question per step", func(t *testing.T) {
		restore, err := buildRestoreSteps(base)
		if err != nil {
			t.Fatalf("buildRestoreSteps: %v", err)
		}
		if len(restore) != 3 {
			t.Fatalf("len = %d, want 3", len(restore))
		}
		for i, want := range base {
			if len(restore[i]) != 1 {
				t.Fatalf("step %d has %d options, want 1", i, len(restore[i]))
			}
			if restore[i][0].ID != want {
				t.Fatalf("step %d id = %s, want %s", i, restore[i][0].ID, want)
			}
			if restore[i][0].Validate != steps[i][0].Validate && restore[i][0].Validate != steps[i][1].Validate && restore[i][0].Validate != steps[i][2].Validate {
				t.Fatalf("step %d lost its validate rule", i)
			}
		}
	})

	t.Run("unknown id errors", func(t *testing.T) {
		bad := append([]string{}, base...)
		bad[1] = "Q999"
		if _, err := buildRestoreSteps(bad); err == nil {
			t.Fatal("expected error for unknown question id")
		}
	})
}

// TestQuestionAnswerPassword derives the strong password from fixed answers
// and a fixed salt: it must be deterministic, 128 chars, and satisfy the
// key-derive password rule (the value lands in the password field as-is).
func TestQuestionAnswerPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	salt := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	answers := []string{"20240101", "shanghai", "@abc"}

	pw1, err := password.ComputeFinalPassword(salt, answers)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	pw2, err := password.ComputeFinalPassword(salt, answers)
	if err != nil {
		t.Fatalf("compute again: %v", err)
	}
	if pw1 != pw2 {
		t.Fatalf("not deterministic:\n  %s\n  %s", pw1, pw2)
	}
	if len(pw1) != 128 {
		t.Fatalf("password length = %d, want 128", len(pw1))
	}
	if err := validation.ValidateKeyDerivePassword(pw1); err != nil {
		t.Fatalf("generated password must satisfy the key-derive rule: %v", err)
	}
}

// TestLoadAndApplyRecoveryConfig verifies the restore pre-load: it parses the
// config, requires a salt, and backfills strength/hint only when unset.
func TestLoadAndApplyRecoveryConfig(t *testing.T) {
	dir := t.TempDir()
	n := 0
	writeConfig := func(t *testing.T, cfg recoveryConfig) string {
		t.Helper()
		n++
		p := filepath.Join(dir, fmt.Sprintf("cfg%d.json", n))
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := recoveryConfig{Version: "1.0.0", Strength: "basic", Salt: "ab12", Hint: "myhint"}

	t.Run("backfills strength and hint", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Config.Value = writeConfig(t, base)
		cfg, err := loadAndApplyRecoveryConfig(p)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.Salt != "ab12" {
			t.Fatalf("salt = %q, want ab12", cfg.Salt)
		}
		if p.Strength.Value != "basic" {
			t.Fatalf("strength = %q, want basic", p.Strength.Value)
		}
		if p.Hint.Value != "myhint" {
			t.Fatalf("hint = %q, want myhint", p.Hint.Value)
		}
	})

	t.Run("keeps explicit strength and hint", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Config.Value = writeConfig(t, base)
		p.Strength.Value = "advanced"
		p.Hint.Value = "override"
		if _, err := loadAndApplyRecoveryConfig(p); err != nil {
			t.Fatalf("load: %v", err)
		}
		if p.Strength.Value != "advanced" {
			t.Fatalf("strength = %q, want advanced", p.Strength.Value)
		}
		if p.Hint.Value != "override" {
			t.Fatalf("hint = %q, want override", p.Hint.Value)
		}
	})

	t.Run("missing salt errors", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Config.Value = writeConfig(t, recoveryConfig{Version: "1.0.0"})
		if _, err := loadAndApplyRecoveryConfig(p); err == nil {
			t.Fatal("expected error for missing salt")
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		p := &keyDeriveParams{}
		p.Config.Value = filepath.Join(dir, "nope.json")
		if _, err := loadAndApplyRecoveryConfig(p); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

// TestRestoreQuestionAnswerSeedChain proves the restore seed equals the
// generate seed: the config stores the very salt used for both the password
// generation and the key derivation, so re-answering the same questions with
// that salt must reproduce the stored keys.
func TestRestoreQuestionAnswerSeedChain(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	salt := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	answers := []string{"20240101", "shanghai", "@abc"}
	input := "ThisIsAFixedProbeInputForGoldenVector2026"

	pw, err := password.ComputeFinalPassword(salt, answers)
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	gen := kdf.DeriveKeySet(input, pw, salt, kdf.StrengthBasic)
	if !gen.Success {
		t.Fatalf("derive: %s", gen.Error)
	}
	if gen.SaltSeed != salt {
		t.Fatalf("derive echoed salt %q, want generate salt", gen.SaltSeed)
	}
	rc := buildRecoveryConfig(gen, "hint", []string{"Q01", "Q06", "Q23"})
	if rc.Salt != salt {
		t.Fatalf("config salt %q != generate salt", rc.Salt)
	}

	pw2, err := password.ComputeFinalPassword(rc.Salt, answers)
	if err != nil {
		t.Fatalf("restore password: %v", err)
	}
	res := kdf.DeriveKeySet(input, pw2, rc.Salt, kdf.StrengthBasic)
	if !res.Success {
		t.Fatalf("restore derive: %s", res.Error)
	}
	if res.UUID != gen.UUID {
		t.Fatalf("restore UUID %q != generate UUID %q", res.UUID, gen.UUID)
	}
	if !kdf.ValidateKeyRecovery(res.Keys[0], rc.UUIDs) {
		t.Fatalf("restored key does not match stored UUIDs")
	}
}

// TestConfigFileReusesQuestionAnswerPasswordField ensures the --use-config-file
// password prompt reuses the standard generate password field (see
// collectConfigPassword), so it offers the same question-answer high-strength
// flow instead of a plain hidden password.
func TestConfigFileReusesQuestionAnswerPasswordField(t *testing.T) {
	f := kdParams.Password
	if f.PromptFn == nil {
		t.Fatal("reused password field must offer the question-answer high-strength prompt")
	}
	if len(f.Rules) != 1 || f.Rules[0].Name != "key_derive_password" {
		t.Fatalf("rules = %+v, want key_derive_password", f.Rules)
	}
}

// TestConfigFileQuestionAnswerSeedChain drives the --use-config-file generate
// entry through the question-answer password flow: mode is resolved to generate,
// the salt is pre-seeded before the password prompt, and the QnA password shares
// that salt with the derivation. The saved recovery config must store the same
// salt and question IDs so restore re-answers the questions and reproduces the
// keys.
func TestConfigFileQuestionAnswerSeedChain(t *testing.T) {
	if testing.Short() {
		t.Skip("argon2 slow in -short")
	}
	p := &keyDeriveParams{}
	p.Mode.Value = "generate"
	preGenerateSaltSeed(p)
	if len(p.Salt.Value) != 128 {
		t.Fatalf("expected pre-seeded 128-hex salt, got %q (len %d)", p.Salt.Value, len(p.Salt.Value))
	}

	answers := []string{"20240101", "shanghai", "@abc"}
	pw, err := password.ComputeFinalPassword(p.Salt.Value, answers)
	if err != nil {
		t.Fatalf("generate password: %v", err)
	}
	input := "ThisIsAFixedProbeInputForGoldenVector2026"

	outPath := filepath.Join(t.TempDir(), "recovery.txt")
	p.Output.Value = outPath
	p.answerIDs = []string{"Q01", "Q06", "Q23"}
	if err := runKeyDeriveGenerate(p, input, pw, "hint", kdf.StrengthBasic); err != nil {
		t.Fatalf("config-file generate: %v", err)
	}

	cfg, err := loadRecoveryConfig(outPath)
	if err != nil {
		t.Fatalf("load saved recovery config: %v", err)
	}
	if cfg.Salt != p.Salt.Value {
		t.Fatalf("config salt %q != pre-seeded salt %q", cfg.Salt, p.Salt.Value)
	}
	if !reflect.DeepEqual(cfg.HintIDs, p.answerIDs) {
		t.Fatalf("config hint IDs %v != answer IDs %v", cfg.HintIDs, p.answerIDs)
	}

	pw2, err := password.ComputeFinalPassword(cfg.Salt, answers)
	if err != nil {
		t.Fatalf("restore password: %v", err)
	}
	res := kdf.DeriveKeySet(input, pw2, cfg.Salt, kdf.StrengthBasic)
	if !res.Success {
		t.Fatalf("restore derive: %s", res.Error)
	}
	if !kdf.ValidateKeyRecovery(res.Keys[0], cfg.UUIDs) {
		t.Fatalf("restored key does not match stored UUIDs")
	}
}
