package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

func TestVaultCompact_WarnsWhenNewerReleaseWroteVault(t *testing.T) {
	tests := []struct {
		name     string
		stamp    string // BinaryVersion when the vault is created
		running  string // BinaryVersion when compact runs
		wantWarn bool
	}{
		{"newer release", "0.12.0", "0.11.0", true},
		{"same release", "0.11.0", "0.11.0", false},
		{"older release", "0.11.0", "0.12.0", false},
		{"unstamped vault", "", "0.11.0", false},
		{"running build is not a release", "0.12.0", "unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := vault.BinaryVersion
			t.Cleanup(func() { vault.BinaryVersion = old })

			path := filepath.Join(t.TempDir(), "vault")
			vault.BinaryVersion = tt.stamp
			if _, err := vault.NewWriter(path); err != nil {
				t.Fatal(err)
			}
			vault.BinaryVersion = tt.running

			resolver := NewMockVaultResolver()
			resolver.VaultPaths = []string{path}
			resolver.VaultEntries = []vault.VaultEntry{{Path: path}}
			stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
			cli := &CLI{vaultResolver: resolver, output: output.NewHandler(stdout, stderr)}

			if err := cli.VaultCompact(false, false, "", 1); err != nil {
				t.Fatalf("VaultCompact: %v", err)
			}

			warnings := cli.Output().GetWarnings()
			if !tt.wantWarn {
				if len(warnings) != 0 || stderr.Len() != 0 {
					t.Fatalf("unexpected warning: %v, stderr %q", warnings, stderr.String())
				}
				return
			}
			if len(warnings) != 1 || warnings[0].Code != output.CodeWarnVaultNewer || !warnings[0].Code.IsWarning() {
				t.Fatalf("warnings = %+v, want one %s", warnings, output.CodeWarnVaultNewer)
			}
			want := "warning: vault " + path + " was written by dotsecenv 0.12.0, newer than this dotsecenv 0.11.0; upgrade dotsecenv before compacting it\n"
			if stderr.String() != want {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
			if !strings.Contains(stdout.String(), "nothing to do") {
				t.Fatalf("compact did not run after the warning: %q", stdout.String())
			}
		})
	}
}
