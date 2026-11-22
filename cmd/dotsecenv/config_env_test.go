package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

// A numeric -v must be resolved against the same config every command uses:
// -c, then DOTSECENV_CONFIG, then the XDG default. The index helpers skipped
// DOTSECENV_CONFIG and read the XDG default instead.
func TestVaultIndex_UsesDOTSECENVConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "other.yaml")
	vault1 := filepath.Join(tmpDir, "vault1")
	vault2 := filepath.Join(tmpDir, "vault2")
	writeTestConfig(t, configPath, []string{vault1, vault2})

	// No config at the XDG default location.
	env := []string{
		"XDG_CONFIG_HOME=" + filepath.Join(tmpDir, "xdg-config"),
		"DOTSECENV_CONFIG=" + configPath,
	}

	if _, stderr, err := runCmdWithEnv(env, "init", "vault", "-v", "2"); err != nil {
		t.Fatalf("init vault -v 2 with DOTSECENV_CONFIG: %v\nstderr: %s", err, stderr)
	}
	if _, err := os.Stat(vault2); err != nil {
		t.Errorf("vault 2 from DOTSECENV_CONFIG was not created: %v", err)
	}
	if _, err := os.Stat(vault1); err == nil {
		t.Errorf("vault 1 should not have been created")
	}

	if _, stderr, err := runCmdWithEnv(env, "secret", "get", "-v", "2"); err != nil {
		t.Errorf("secret get -v 2 with DOTSECENV_CONFIG: %v\nstderr: %s", err, stderr)
	}
}
