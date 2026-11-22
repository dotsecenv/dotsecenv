package main_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// doctor -v N --fix must only touch vault N. The format check used to collect
// every outdated configured vault, so --fix upgraded all of them.
func TestDoctor_FixOnlyUpgradesSelectedVault(t *testing.T) {
	tmpDir := t.TempDir()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "pkg", "dotsecenv", "vault", "testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	vault1 := filepath.Join(tmpDir, "vault1")
	vault2 := filepath.Join(tmpDir, "vault2")
	for _, p := range []string{vault1, vault2} {
		if err := os.WriteFile(p, fixture, 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Explicit upgrades, so loading the vaults does not upgrade them first.
	configPath := filepath.Join(tmpDir, "config.yaml")
	config := fmt.Sprintf(`approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
  - %s
behavior:
  require_explicit_vault_upgrade: true
gpg:
  program: PATH
`, vault1, vault2)
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	env := doctorEnv(t) // doctor exits 4 without a live gpg-agent
	if _, stderr, err := runCmdWithEnv(env, "-c", configPath, "doctor", "-v", "1", "--fix"); err != nil {
		t.Fatalf("doctor -v 1 --fix: %v\nstderr: %s", err, stderr)
	}

	for path, want := range map[string]int{vault1: vault.LatestFormatVersion, vault2: 1} {
		got, err := vault.DetectVaultVersion(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s: format v%d, want v%d", filepath.Base(path), got, want)
		}
	}
}
