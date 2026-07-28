package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/crypto"
	"go-cipher-cli/internal/fusion"
	"go-cipher-cli/internal/kdf"
)

// hashCmd mirrors CryptoTools.hashText: hash stdin/file text with a named algorithm.
var hashCmd = &cobra.Command{
	Use:   "hash [text]",
	Short: "Hash text with MD5/SHA1/SHA2/SHA3 (mirrors CryptoTools.hashText)",
	Long: `Hash the given text (or the single argument) with the chosen algorithm.
Supported: md5, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256,
sha3-384, sha3-512.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		algo, _ := cmd.Flags().GetString("algo")
		res := crypto.HashText(args[0], algo)
		if !res.Success {
			return fmt.Errorf("%s", res.Error)
		}
		fmt.Println(res.Data)
		return nil
	},
}

// hmacCmd mirrors HmacTools.hashText.
var hmacCmd = &cobra.Command{
	Use:   "hmac [data]",
	Short: "Compute HMAC of text (mirrors HmacTools.hashText)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		algo, _ := cmd.Flags().GetString("algo")
		key, _ := cmd.Flags().GetString("key")
		res := crypto.HMAC(args[0], algo, key)
		if !res.Success {
			return fmt.Errorf("%s", res.Error)
		}
		fmt.Println(res.Data)
		return nil
	},
}

// fuseCmd mirrors computeFinalPassword (normalize + fusePasswords).
var fuseCmd = &cobra.Command{
	Use:   "fuse",
	Short: "Fuse multiple passwords into one (mirrors computeFinalPassword)",
	Long: `Combine one or more passwords into a single fused password using the
frontend password-fusion algorithm (normalize + fusePasswords). Requires a salt
and 1-3 passwords.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		salt, _ := cmd.Flags().GetString("salt")
		pws, _ := cmd.Flags().GetStringSlice("password")
		if salt == "" {
			return fmt.Errorf("--salt is required")
		}
		if len(pws) == 0 {
			return fmt.Errorf("at least one --password is required")
		}
		fmt.Println(fusion.ComputeFinalPassword(salt, pws))
		return nil
	},
}

// recoverCmd mirrors validateKeyRecovery (first-8 + last-8 against stored uuids).
var recoverCmd = &cobra.Command{
	Use:   "recover [generated-key]",
	Short: "Validate key recovery (mirrors validateKeyRecovery)",
	Long: `Check whether a generated key's first-8 + last-8 chars appear in the
stored --uuid list (the web tool's key-recovery verification).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuids, _ := cmd.Flags().GetStringSlice("uuid")
		if kdf.ValidateKeyRecovery(args[0], uuids) {
			fmt.Println("MATCH")
			return nil
		}
		fmt.Println("NO MATCH")
		return nil
	},
}

// hintMatchCmd mirrors validateHintAndKeysUuidMatch.
var hintMatchCmd = &cobra.Command{
	Use:   "hint-match",
	Short: "Validate hint/key UUID match (mirrors validateHintAndKeysUuidMatch)",
	Long: `Compare the KEYUUID embedded in an encrypted hint against a meta hint.
Both inputs are read from --encrypted and --meta.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		enc, _ := cmd.Flags().GetString("encrypted")
		meta, _ := cmd.Flags().GetString("meta")
		if container.ValidateHintAndKeysUuidMatch(enc, meta) {
			fmt.Println("MATCH")
		} else {
			fmt.Println("NO MATCH")
		}
		return nil
	},
}

func init() {
	hashCmd.Flags().String("algo", "sha256", "hash algorithm")
	hmacCmd.Flags().String("algo", "hmac-sha256", "HMAC algorithm")
	hmacCmd.Flags().String("key", "", "HMAC key")
	_ = hmacCmd.MarkFlagRequired("key")
	fuseCmd.Flags().String("salt", "", "salt string used by the fusion algorithm")
	fuseCmd.Flags().StringSliceP("password", "p", nil, "password (repeatable, 1-3)")
	recoverCmd.Flags().StringSlice("uuid", nil, "stored uuid list (repeatable)")
	_ = recoverCmd.MarkFlagRequired("uuid")
	hintMatchCmd.Flags().String("encrypted", "", "encrypted hint text")
	hintMatchCmd.Flags().String("meta", "", "meta hint text")
	_ = hintMatchCmd.MarkFlagRequired("encrypted")
	_ = hintMatchCmd.MarkFlagRequired("meta")

	// rootCmd.AddCommand(hashCmd)
	// rootCmd.AddCommand(hmacCmd)
	// rootCmd.AddCommand(fuseCmd)
	// rootCmd.AddCommand(recoverCmd)
	// rootCmd.AddCommand(hintMatchCmd)
}
