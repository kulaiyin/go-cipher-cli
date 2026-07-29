package cmd

// Commented out: hash/hmac/fuse/recover/hint-match/keygen commands not yet implemented.
// func TestHashCmd(t *testing.T) {
// 	// sha256("hello") known vector.
// 	out, code := runCLI(t, "hash", "hello", "--algo", "sha256")
// 	if code != 0 {
// 		t.Fatalf("hash failed: %s", out)
// 	}
// 	got := strings.TrimSpace(out)
// 	if got != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
// 		t.Errorf("hash sha256(hello) = %s", got)
// 	}
// }
//
// func TestHashCmd_Sha3_512(t *testing.T) {
// 	out, code := runCLI(t, "hash", "hello", "--algo", "sha3-512")
// 	if code != 0 {
// 		t.Fatalf("hash failed: %s", out)
// 	}
// 	got := strings.TrimSpace(out)
// 	if got != "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976" {
// 		t.Errorf("hash sha3-512(hello) = %s", got)
// 	}
// }
//
// func TestHmacCmd(t *testing.T) {
// 	out, code := runCLI(t, "hmac", "data", "--algo", "hmac-sha256", "--key", "secret")
// 	if code != 0 {
// 		t.Fatalf("hmac failed: %s", out)
// 	}
// 	if strings.TrimSpace(out) == "" {
// 		t.Error("empty hmac output")
// 	}
// }
//
// func TestFuseCmd_MatchesGolden(t *testing.T) {
// 	// fusePasswords golden vector: salt a76fdc37b135f1c3, passwords [123456789, shanghai, @]
// 	v := testvectors.MustLoad()
// 	want := v.FusePasswords.Basic[0].Out
// 	out, code := runCLI(t, "fuse", "--salt", "a76fdc37b135f1c3",
// 		"-p", "123456789", "-p", "shanghai", "-p", "@")
// 	if code != 0 {
// 		t.Fatalf("fuse failed: %s", out)
// 	}
// 	if strings.TrimSpace(out) != want {
// 		t.Errorf("fuse = %q, want %q", strings.TrimSpace(out), want)
// 	}
// }
//
// func TestRecoverCmd(t *testing.T) {
// 	// key whose first8+last8 = "abcdef12"+"12345678"
// 	out, code := runCLI(t, "recover", "abcdef1234567890WVWXYZ12345678", "--uuid", "abcdef1212345678", "--uuid", "deadbeef")
// 	if code != 0 {
// 		t.Fatalf("recover failed: %s", out)
// 	}
// 	if strings.TrimSpace(out) != "MATCH" {
// 		t.Errorf("recover = %s, want MATCH", out)
// 	}
// 	out, _ = runCLI(t, "recover", "abcdef1234567890WVWXYZ12345678", "--uuid", "nomatch00000000")
// 	if strings.TrimSpace(out) != "NO MATCH" {
// 		t.Errorf("recover (no match) = %s, want NO MATCH", out)
// 	}
// }
//
// func TestHintMatchCmd(t *testing.T) {
// 	out, code := runCLI(t, "hint-match",
// 		"--encrypted", "KEYUUID: ab12cd34ef",
// 		"--meta", "KEYUUID: ab12cd34ef")
// 	if code != 0 {
// 		t.Fatalf("hint-match failed: %s", out)
// 	}
// 	if strings.TrimSpace(out) != "MATCH" {
// 		t.Errorf("hint-match = %s, want MATCH", out)
// 	}
// 	out, _ = runCLI(t, "hint-match",
// 		"--encrypted", "KEYUUID: ab12cd34ef",
// 		"--meta", "KEYUUID: 0000000000")
// 	if strings.TrimSpace(out) != "NO MATCH" {
// 		t.Errorf("hint-match (diff) = %s, want NO MATCH", out)
// 	}
// }
//
// func TestKeygenCmd_SinglePassword(t *testing.T) {
// 	if testing.Short() {
// 		t.Skip("argon2 slow in -short")
// 	}
// 	out, code := runCLI(t, "keygen", "-p", "testpw", "--salt", strings.Repeat("01", 64), "--hash-length", "32")
// 	if code != 0 {
// 		t.Fatalf("keygen failed: %s", out)
// 	}
// 	if !strings.Contains(out, "key (hex):") {
// 		t.Errorf("keygen output missing key line:\n%s", out)
// 	}
// }
