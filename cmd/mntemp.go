package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/param"
	"go-cipher-cli/internal/tmpmount"
	"go-cipher-cli/internal/util"
)

const (
	mntempMaxSizeMB     = 512
	mntempDefaultSizeMB = 24
	// mntempDefaultName is the mount point name used when --name is omitted.
	mntempDefaultName = "default"
)

// mntempParams declares the parameters of the mntemp command. The operation
// (mount|umount) is a positional argument; the remaining parameters are flags.
type mntempParams struct {
	Action param.Field
	Name   param.Field
	Size   param.Field
	Path   param.Field

	// SizeMB is the parsed size (MB) set during validate().
	SizeMB int

	// MountPath is the resolved mount path set during afterStandardize.
	MountPath string
}

var mtParams mntempParams

var mntempCmd = &cobra.Command{
	Use:          "mntemp <mount|umount>",
	Short:        "placeholder",
	Long:         "placeholder",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			mtParams.Action.Value = strings.TrimSpace(args[0])
		}
		// Drive the shared declarative lifecycle; runMntemp executes the body.
		return mtSet.run(&mtParams)
	},
}

// fieldEntries binds each parameter to its flag name and value target, in
// validation/prompt order.
func (p *mntempParams) fieldEntries() []fieldEntry {
	return []fieldEntry{
		{&p.Action, &p.Action.Value, "action"},
		{&p.Name, &p.Name.Value, "name"},
		{&p.Size, &p.Size.Value, "size"},
		{&p.Path, &p.Path.Value, "path"},
	}
}

// resolveMntempPath returns the effective mount path: --path if given (with ~
// expanded), otherwise the platform default /tmp/mntemp/<name>/.
func resolveMntempPath(name, customPath string) string {
	if customPath != "" {
		return expandHomeDir(customPath)
	}
	return tmpmount.DefaultMountPath(name)
}

// expandHomeDir expands a leading ~ to the user's home directory. A bare "~"
// is expanded too; other paths are returned unchanged.
func expandHomeDir(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func mntempMount(p *mntempParams) error {
	// Highlight the mount path, the volatile-memory warning, and the cleanup
	// command in the start hint so users notice them at a glance.
	fmt.Println(i18n.TWithData("mntemp.mount.hint.start", map[string]interface{}{
		"Path":     util.Bold(util.Yellow(p.MountPath)),
		"Shutdown": util.Bold(util.Yellow(i18n.T("mntemp.mount.hint.shutdown"))),
		"Umount":   util.Bold(util.Yellow(fmt.Sprintf("mntemp umount --name %s", p.Name.Value))),
	}))

	if _, err := os.Stat(p.MountPath); err == nil {
		return fmt.Errorf("%s", i18n.TWithData("mntemp.mount.error.path_exists", map[string]interface{}{
			"Path": p.MountPath,
		}))
	}

	return mountVolatile(p.MountPath, p.SizeMB, p.Name.Value)
}

// mountVolatile mounts a RAM-backed filesystem at path with the given size,
// retrying elevated via sudo on a terminal when the native mount fails for
// privilege reasons, and prints the outcome. Shared by mntemp and the commands
// that auto-mount a volatile save location (e.g. key-derive).
func mountVolatile(path string, sizeMB int, name string) error {
	res, err := tmpmount.Mount(path, sizeMB, name)
	if err != nil {
		return err
	}

	// The native mount failed. When the cause is missing privileges and we're
	// on a terminal, offer a sudo retry before falling back to a directory.
	if res.Backend == tmpmount.BackendDir && tmpmount.IsPrivilegeError(res.FallbackErr) && param.IsStdinTerminal() {
		confirmed, _ := param.Confirm(i18n.T("mntemp.mount.prompt.sudo"), true)
		if confirmed {
			sudoRes, sudoErr := tmpmount.MountWithSudo(path, sizeMB, name)
			if sudoErr == nil {
				res = sudoRes
			} else {
				fmt.Fprintln(os.Stderr, i18n.TWithData("mntemp.mount.error.sudo_failed", map[string]interface{}{
					"Err": sudoErr,
				}))
			}
		}
	}

	printMntempMountResult(res, name)
	return nil
}

// mntempSaveDefault returns the default save path for a command's output: the
// volatile mntemp command directory when mounted (or after the user accepts
// mounting on a terminal), otherwise fallback. Declining or a failed mount
// returns fallback silently; the volatile notice is printed when the mount is
// used. Shared by commands that default their output into the volatile
// filesystem (e.g. key-derive, data-cipher decrypt).
func mntempSaveDefault(command, fallback string) string {
	root := tmpmount.DefaultMountPath(mntempDefaultName)
	if !tmpmount.IsMounted(root) {
		if !param.IsStdinTerminal() {
			return fallback
		}
		confirmed, err := param.Confirm(i18n.T("mntemp.prompt.mount_confirm"), true)
		if err != nil || !confirmed {
			return fallback
		}
		if err := mountVolatile(root, mntempDefaultSizeMB, mntempDefaultName); err != nil {
			fmt.Fprintln(os.Stderr, i18n.TWithData("mntemp.error.mount_failed", map[string]interface{}{
				"Err": err,
			}))
			return fallback
		}
	}
	dir, err := tmpmount.CommandDir(mntempDefaultName, command)
	if err != nil {
		return fallback
	}
	defaultPath := filepath.Join(dir, filepath.Base(fallback))
	fmt.Println(i18n.TWithData("mntemp.output.note", map[string]interface{}{
		"Path": defaultPath,
	}))
	return defaultPath
}

// isVolatilePath reports whether p points inside the active volatile mntemp
// mount, used to decide whether a saved file needs a "move it elsewhere" hint.
func isVolatilePath(p string) bool {
	root := tmpmount.DefaultMountPath(mntempDefaultName)
	if !tmpmount.IsMounted(root) {
		return false
	}
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && rel != "")
}

func printMntempMountResult(res *tmpmount.Result, name string) {
	switch res.Backend {
	case tmpmount.BackendTmpfs:
		fmt.Println(i18n.TWithData("mntemp.mount.success.tmpfs", map[string]interface{}{
			"Path": res.Path, "Size": res.SizeMB,
		}))
	case tmpmount.BackendRamDisk:
		fmt.Println(i18n.TWithData("mntemp.mount.success.ramdisk", map[string]interface{}{
			"Path": res.Path, "Size": res.SizeMB,
		}))
	default:
		reason := "unsupported"
		if res.FallbackErr != nil {
			reason = res.FallbackErr.Error()
		}
		fmt.Fprintln(os.Stderr, i18n.TWithData("mntemp.mount.success.dir", map[string]interface{}{
			"Path": res.Path, "Size": res.SizeMB, "Err": reason,
		}))
		fmt.Println(i18n.TWithData("mntemp.mount.hint.dir", map[string]interface{}{
			"Path": res.Path, "Name": name,
		}))
	}
}

func mntempUmount(p *mntempParams) error {
	if _, err := os.Stat(p.MountPath); os.IsNotExist(err) {
		return fmt.Errorf("%s", i18n.TWithData("mntemp.umount.error.not_found", map[string]interface{}{
			"Path": p.MountPath,
		}))
	}
	if err := tmpmount.Umount(p.MountPath); err != nil {
		// A mount created with sudo needs elevated privileges to detach.
		// Offer a sudo retry on a terminal before giving up.
		if tmpmount.IsPrivilegeError(err) && param.IsStdinTerminal() {
			confirmed, _ := param.Confirm(i18n.T("mntemp.umount.prompt.sudo"), true)
			if confirmed {
				if sudoErr := tmpmount.UmountWithSudo(p.MountPath); sudoErr == nil {
					fmt.Println(i18n.TWithData("mntemp.umount.success", map[string]interface{}{
						"Path": p.MountPath,
					}))
					return nil
				} else {
					fmt.Fprintln(os.Stderr, i18n.TWithData("mntemp.umount.error.sudo_failed", map[string]interface{}{
						"Err": sudoErr,
					}))
				}
			}
		}
		return fmt.Errorf("%s: %w", i18n.TWithData("mntemp.umount.error.failed", map[string]interface{}{
			"Path": p.MountPath,
		}), err)
	}
	fmt.Println(i18n.TWithData("mntemp.umount.success", map[string]interface{}{
		"Path": p.MountPath,
	}))
	return nil
}

// runMntemp executes the command after all params are resolved (flags +
// interactive): it dispatches to mount or umount based on the action.
func runMntemp(p *mntempParams) error {
	if p.Action.Value == "umount" {
		return mntempUmount(p)
	}
	return mntempMount(p)
}

// mtSet drives the shared declarative lifecycle for the mntemp command:
// normalize + validate, cross-field resolution (size parse + mount path), and
// the mount/umount dispatch.
var mtSet = paramSet[mntempParams]{
	fields: func(p *mntempParams) []fieldEntry { return p.fieldEntries() },
	normalize: func(p *mntempParams) {
		p.Action.Value = strings.ToLower(strings.TrimSpace(p.Action.Value))
		p.Name.Value = strings.TrimSpace(p.Name.Value)
		p.Size.Value = strings.TrimSpace(p.Size.Value)
	},
	afterStandardize: func(p *mntempParams) error {
		if p.Action.Value == "mount" {
			p.SizeMB, _ = strconv.Atoi(p.Size.Value)
		}
		p.MountPath = resolveMntempPath(p.Name.Value, p.Path.Value)
		return nil
	},
	execute: runMntemp,
}

func init() {
	i18n.MustInit("")
	refreshCmdDescs = append(refreshCmdDescs, func() {
		mntempCmd.Short = i18n.T("mntemp.short")
		mntempCmd.Long = i18n.T("mntemp.long")
	})

	// Field declarations: type metadata, requiredness, and validation rules.
	// The operation is a positional argument whose value must be mount|umount.
	mtParams.Action.Allowed = []string{"mount", "umount"}
	mtParams.Action.Required = true
	mtParams.Action.Interactive = false
	// name is required for mount, and for umount only when no path was given.
	mtParams.Name.Required = true
	mtParams.Name.Interactive = false
	mtParams.Name.Visible = func(v param.FieldValues) bool {
		return v["action"] == "mount" || (v["action"] == "umount" && v["path"] == "")
	}
	// size must be an integer in [1, mntempMaxSizeMB]; only meaningful for mount.
	mtParams.Size.Required = true
	mtParams.Size.Interactive = false
	mtParams.Size.Rules = []param.Rule{
		{"int_range", []string{"1", strconv.Itoa(mntempMaxSizeMB)}},
	}
	mtParams.Size.Visible = func(v param.FieldValues) bool {
		return v["action"] == "mount"
	}
	mtParams.Path.Interactive = false

	// Hook: resolve the effective mount path (custom or default).

	mntempCmd.Flags().StringVar(&mtParams.Name.Value, "name", mntempDefaultName, i18n.T("mntemp.flag.name"))
	mntempCmd.Flags().StringVar(&mtParams.Size.Value, "size", strconv.Itoa(mntempDefaultSizeMB), i18n.T("mntemp.flag.size"))
	mntempCmd.Flags().StringVar(&mtParams.Path.Value, "path", "", i18n.T("mntemp.flag.path"))

	rootCmd.AddCommand(mntempCmd)
}
