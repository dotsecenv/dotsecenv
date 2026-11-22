package main_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// Commands that only read must not rewrite a vault. With the default
// require_explicit_vault_upgrade: false, loading an outdated vault upgraded
// it in place, so validate, describe, doctor and secret get all wrote to it.
func TestReadOnlyCommands_DoNotUpgradeVault(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "pkg", "dotsecenv", "vault", "testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeTestConfig(t, configPath, []string{vaultPath})
	env := []string{"GNUPGHOME=" + filepath.Join(tmpDir, "gnupg")}

	for _, args := range [][]string{
		{"validate"},
		{"vault", "describe"},
		{"vault", "doctor"},
		{"doctor"},
		{"secret", "get"},
	} {
		if err := os.WriteFile(vaultPath, fixture, 0600); err != nil {
			t.Fatal(err)
		}
		_, stderr, _ := runCmdWithEnv(env, append([]string{"-c", configPath}, args...)...)
		after, err := os.ReadFile(vaultPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fixture, after) {
			t.Errorf("%s rewrote the vault", strings.Join(args, " "))
		}
		if !strings.Contains(stderr, "dotsecenv doctor --fix") {
			t.Errorf("%s: want a hint naming the upgrade command, got stderr: %s", strings.Join(args, " "), stderr)
		}
	}

	// The upgrade itself stays available, explicitly.
	if err := os.WriteFile(vaultPath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _ = runCmdWithEnv(env, "-c", configPath, "doctor", "--fix")
	if got, err := vault.DetectVaultVersion(vaultPath); err != nil || got != vault.LatestFormatVersion {
		t.Errorf("doctor --fix: format v%d (err %v), want v%d", got, err, vault.LatestFormatVersion)
	}
}
