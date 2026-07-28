package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/container"
	"go-cipher-cli/internal/crypto"
	"go-cipher-cli/internal/fusion"
	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/kdf"
)

// hashCmd hashes stdin/file text with a named algorithm.
var hashCmd = &cobra.Command{
	Use:   "hash [text]",
	Short: "placeholder",
	Long:  "placeholder",
	Args:  cobra.ExactArgs(1),
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

// hmacCmd computes an HMAC over stdin/file text.
var hmacCmd = &cobra.Command{
	Use:   "hmac [data]",
	Short: "placeholder",
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

// fuseCmd fuses passwords (normalize + fuse) into a single strengthened string.
var fuseCmd = &cobra.Command{
	Use:   "fuse",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		salt, _ := cmd.Flags().GetString("salt")
		pws, _ := cmd.Flags().GetStringSlice("password")
		if salt == "" {
			return errors.New(i18n.T("fuse.error.salt_required"))
		}
		if len(pws) == 0 {
			return errors.New(i18n.T("fuse.error.password_required"))
		}
		fmt.Println(fusion.ComputeFinalPassword(salt, pws))
		return nil
	},
}

// recoverCmd checks first-8 + last-8 of a key against stored uuids.
var recoverCmd = &cobra.Command{
	Use:   "recover [generated-key]",
	Short: "placeholder",
	Long:  "placeholder",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuids, _ := cmd.Flags().GetStringSlice("uuid")
		if kdf.ValidateKeyRecovery(args[0], uuids) {
			fmt.Println(i18n.T("recover.output.match"))
			return nil
		}
		fmt.Println(i18n.T("recover.output.no_match"))
		return nil
	},
}

// hintMatchCmd checks whether the encrypted hint and meta hint reference the same key UUID.
var hintMatchCmd = &cobra.Command{
	Use:   "hint-match",
	Short: "placeholder",
	Long:  "placeholder",
	RunE: func(cmd *cobra.Command, args []string) error {
		enc, _ := cmd.Flags().GetString("encrypted")
		meta, _ := cmd.Flags().GetString("meta")
		if container.ValidateHintAndKeysUuidMatch(enc, meta) {
			fmt.Println(i18n.T("hint_match.output.match"))
		} else {
			fmt.Println(i18n.T("hint_match.output.no_match"))
		}
		return nil
	},
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		hashCmd.Short = i18n.T("hash.short")
		hashCmd.Long = i18n.T("hash.long")
		hmacCmd.Short = i18n.T("hmac.short")
		fuseCmd.Short = i18n.T("fuse.short")
		fuseCmd.Long = i18n.T("fuse.long")
		recoverCmd.Short = i18n.T("recover.short")
		recoverCmd.Long = i18n.T("recover.long")
		hintMatchCmd.Short = i18n.T("hint_match.short")
		hintMatchCmd.Long = i18n.T("hint_match.long")
	})

	hashCmd.Flags().String("algo", "sha256", i18n.T("hash.flag.algo"))
	hmacCmd.Flags().String("algo", "hmac-sha256", i18n.T("hmac.flag.algo"))
	hmacCmd.Flags().String("key", "", i18n.T("hmac.flag.key"))
	_ = hmacCmd.MarkFlagRequired("key")
	fuseCmd.Flags().String("salt", "", i18n.T("fuse.flag.salt"))
	fuseCmd.Flags().StringSliceP("password", "p", nil, i18n.T("fuse.flag.password"))
	recoverCmd.Flags().StringSlice("uuid", nil, i18n.T("recover.flag.uuid"))
	_ = recoverCmd.MarkFlagRequired("uuid")
	hintMatchCmd.Flags().String("encrypted", "", i18n.T("hint_match.flag.encrypted"))
	hintMatchCmd.Flags().String("meta", "", i18n.T("hint_match.flag.meta"))
	_ = hintMatchCmd.MarkFlagRequired("encrypted")
	_ = hintMatchCmd.MarkFlagRequired("meta")

	rootCmd.AddCommand(hashCmd)
	rootCmd.AddCommand(hmacCmd)
	rootCmd.AddCommand(fuseCmd)
	rootCmd.AddCommand(recoverCmd)
	rootCmd.AddCommand(hintMatchCmd)
}
