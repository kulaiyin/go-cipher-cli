package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-cipher-cli/internal/i18n"
	"go-cipher-cli/internal/param"
)

func TestResolveMntempPath(t *testing.T) {
	tests := []struct {
		name       string
		customPath string
		wantSuffix string // resolved path must end with this
	}{
		{"default", "", filepath.Join("mntemp", "build-env")},
		{"custom", "/var/tmp/work", "work"},
		{"tilde", "~/work", "work"},
		{"bare tilde", "~", ""}, // expands to home
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMntempPath("build-env", tt.customPath)
			if tt.customPath == "" {
				want := filepath.Join(os.TempDir(), "mntemp", "build-env")
				if got != want {
					t.Errorf("resolveMntempPath() = %q, want %q", got, want)
				}
				return
			}
			if !strings.HasSuffix(got, tt.wantSuffix) {
				t.Errorf("resolveMntempPath() = %q, want suffix %q", got, tt.wantSuffix)
			}
			if tt.name == "bare tilde" {
				home, _ := os.UserHomeDir()
				if got != home {
					t.Errorf("bare tilde = %q, want home %q", got, home)
				}
			}
		})
	}
}

func newMntempParams(op, name, size, path string) mntempParams {
	return mntempParams{
		Action: param.Field{
			Value:    op,
			Allowed:  []string{"mount", "umount"},
			Required: true,
		},
		Name: param.Field{
			Value:    name,
			Required: true,
			Visible: func(v param.FieldValues) bool {
				return v["action"] == "mount" || (v["action"] == "umount" && v["path"] == "")
			},
		},
		Size: param.Field{
			Value:    size,
			Required: true,
			Rules:    []param.Rule{{"int_range", []string{"1", "512"}}},
			Visible: func(v param.FieldValues) bool {
				return v["action"] == "mount"
			},
		},
		Path: param.Field{Value: path},
	}
}

func TestMntempValidate(t *testing.T) {
	i18n.MustInit("")
	tests := []struct {
		op   string
		name string
		size string
		path string
		want string // expected i18n key of the error; "" means success
	}{
		{"", "build-env", "256", "", "param.error.required"},
		{"mountx", "build-env", "256", "", "param.error.allowed"},
		{"mount", "", "256", "", "param.error.required"},
		{"mount", "build-env", "", "", "param.error.required"},
		{"mount", "build-env", "0", "", "param.error.int_range"},
		{"mount", "build-env", "513", "", "param.error.int_range"},
		{"mount", "build-env", "-1", "", "param.error.int_range"},
		{"mount", "build-env", "abc", "", "param.error.int_range"},
		{"umount", "", "", "", "param.error.required"},
		{"umount", "build-env", "", "", ""},
		{"umount", "", "", "/var/tmp/x", ""},
		{"mount", "build-env", "256", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.op+"_"+tt.name+"_"+tt.size+tt.path, func(t *testing.T) {
			p := newMntempParams(tt.op, tt.name, tt.size, tt.path)
			err := p.validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() = nil, want error %s", tt.want)
			}
			var wantMsg string
			switch tt.want {
			case "param.error.required":
				wantMsg = i18n.TWithData(tt.want, map[string]interface{}{"Flag": "name"})
				if tt.op == "" {
					wantMsg = i18n.TWithData(tt.want, map[string]interface{}{"Flag": "action"})
				} else if tt.op == "mount" && tt.name != "" {
					wantMsg = i18n.TWithData(tt.want, map[string]interface{}{"Flag": "size"})
				}
			case "param.error.allowed":
				wantMsg = i18n.TWithData(tt.want, map[string]interface{}{
					"Flag": "action", "Value": tt.op, "Allowed": "mount, umount",
				})
			case "param.error.int_range":
				wantMsg = i18n.TWithData(tt.want, map[string]interface{}{
					"Flag": "size", "Min": 1, "Max": mntempMaxSizeMB,
				})
			default:
				wantMsg = i18n.T(tt.want)
			}
			if !strings.Contains(err.Error(), wantMsg) {
				t.Errorf("validate() error = %q, want containing %q", err, wantMsg)
			}
		})
	}
}

func TestMntempSizeParsed(t *testing.T) {
	p := newMntempParams("mount", "build-env", "256", "")
	if err := p.standardize(); err != nil {
		t.Fatalf("standardize() error = %v", err)
	}
	if p.SizeMB != 256 {
		t.Errorf("SizeMB = %d, want 256", p.SizeMB)
	}
}
