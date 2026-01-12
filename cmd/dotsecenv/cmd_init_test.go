package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// skipIfNoGPG skips the test if GPG is not available
func skipIfNoGPG(t *testing.T) {
	t.Helper()
	_, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("GPG not available, skipping test")
	}
}

// configForTest represents the config file structure for test assertions
type configForTest struct {
	ApprovedAlgorithms []struct {
		Algo    string   `yaml:"algo"`
		Curves  []string `yaml:"curves,omitempty"`
		MinBits int      `yaml:"min_bits"`
	} `yaml:"approved_algorithms"`
	Fingerprint string   `yaml:"fingerprint,omitempty"`
	Vault       []string `yaml:"vault"`
	Strict      bool     `yaml:"strict"`
	Behavior    struct {
		RequireExplicitVaultUpgrade *bool `yaml:"require_explicit_vault_upgrade,omitempty"`
		RestrictToConfiguredVaults  *bool `yaml:"restrict_to_configured_vaults,omitempty"`
	} `yaml:"behavior,omitempty"`
	GPG struct {
		Program string `yaml:"program,omitempty"`
	} `yaml:"gpg,omitempty"`
}

func loadConfigForTest(t *testing.T, path string) configForTest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	var cfg configForTest
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse config file: %v", err)
	}
	return cfg
}

func TestInitConfig_HasBehaviorSection(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify behavior settings are present and defaulted to false
	cfg := loadConfigForTest(t, configPath)

	if cfg.Behavior.RequireExplicitVaultUpgrade == nil {
		t.Errorf("expected require_explicit_vault_upgrade to be set")
	} else if *cfg.Behavior.RequireExplicitVaultUpgrade != false {
		t.Errorf("expected require_explicit_vault_upgrade=false, got %v", *cfg.Behavior.RequireExplicitVaultUpgrade)
	}

	if cfg.Behavior.RestrictToConfiguredVaults == nil {
		t.Errorf("expected restrict_to_configured_vaults to be set")
	} else if *cfg.Behavior.RestrictToConfiguredVaults != false {
		t.Errorf("expected restrict_to_configured_vaults=false, got %v", *cfg.Behavior.RestrictToConfiguredVaults)
	}
}

func TestInitConfig_LoginFlag(t *testing.T) {
	// The --login flag now creates a signed login proof, which requires GPG
	// to sign the proof. Skip this test if GPG is not available.
	skipIfNoGPG(t)

	// This test requires a real GPG key - we need to use e2e tests for proper validation
	// For now, we just test the flag parsing without actual GPG operations
	t.Skip("TestInitConfig_LoginFlag requires real GPG key - tested in e2e")
}

func TestInitConfig_BehaviorCommentsExist(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config failed: %v\nSTDERR: %s", err, stderr)
	}

	// Read raw config file to check for comments
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	content := string(data)

	// Verify comments are present
	expectedComments := []string{
		"# Behavior settings control how dotsecenv handles edge cases",
		"# Prevent automatic vault format upgrades",
		"# Ignore CLI -v flags",
	}

	for _, comment := range expectedComments {
		if !strings.Contains(content, comment) {
			t.Errorf("expected config to contain comment %q", comment)
		}
	}
}

func TestInitConfig_NoStrictFieldInOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config failed: %v\nSTDERR: %s", err, stderr)
	}

	// Read raw config and verify strict field is not present
	// (we use behavior section now instead)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "strict:") {
		t.Errorf("expected config to NOT contain 'strict:' field, but it does")
	}
}

func TestInitConfig_DefaultFingerprintIsEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config without --login flag
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify fingerprint defaults to empty
	cfg := loadConfigForTest(t, configPath)
	if cfg.Fingerprint != "" {
		t.Errorf("expected fingerprint to be empty by default, got fingerprint=%q", cfg.Fingerprint)
	}
}

func TestInitConfig_NoGPGProgram(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config with --no-gpg-program
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config --no-gpg-program failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify gpg.program is empty
	cfg := loadConfigForTest(t, configPath)
	if cfg.GPG.Program != "" {
		t.Errorf("expected gpg.program to be empty, got %q", cfg.GPG.Program)
	}

	// Verify stderr contains the skip message
	if !strings.Contains(stderr, "Skipping GPG program detection") {
		t.Errorf("expected stderr to contain skip message, got: %s", stderr)
	}
}

func TestInitConfig_GPGProgram(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	customGPGPath := "/custom/path/to/gpg"

	// Run init config with --gpg-program
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--gpg-program", customGPGPath)
	if err != nil {
		t.Fatalf("init config --gpg-program failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify gpg.program is set to the custom path
	cfg := loadConfigForTest(t, configPath)
	if cfg.GPG.Program != customGPGPath {
		t.Errorf("expected gpg.program=%q, got %q", customGPGPath, cfg.GPG.Program)
	}
}

func TestInitConfig_MutuallyExclusiveGPGFlags(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config with both --gpg-program and --no-gpg-program (should fail)
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--gpg-program", "/path/to/gpg", "--no-gpg-program")
	if err == nil {
		t.Fatalf("expected init config to fail with mutually exclusive flags, but it succeeded")
	}

	// Verify error message
	if !strings.Contains(stderr, "--no-gpg-program and --gpg-program cannot be used together") {
		t.Errorf("expected mutual exclusion error message, got: %s", stderr)
	}
}

func TestInitConfig_ConfigAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a config file first
	_, _, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("first init config failed: %v", err)
	}

	// Try to init again (should fail)
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err == nil {
		t.Fatalf("expected second init config to fail, but it succeeded")
	}

	// Verify error message
	if !strings.Contains(stderr, "already exists") {
		t.Errorf("expected 'already exists' error message, got: %s", stderr)
	}
}

func TestInitConfig_WithVaultPaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath1 := filepath.Join(tmpDir, "vault1.yaml")
	vaultPath2 := filepath.Join(tmpDir, "vault2.yaml")

	// Run init config with -v flags
	_, stderr, err := runCmd("init", "config", "-c", configPath, "-v", vaultPath1, "-v", vaultPath2, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config with vaults failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify vault paths are in config
	cfg := loadConfigForTest(t, configPath)
	if len(cfg.Vault) != 2 {
		t.Errorf("expected 2 vaults, got %d", len(cfg.Vault))
	}

	found1, found2 := false, false
	for _, v := range cfg.Vault {
		if v == vaultPath1 {
			found1 = true
		}
		if v == vaultPath2 {
			found2 = true
		}
	}
	if !found1 {
		t.Errorf("expected vault path %q in config", vaultPath1)
	}
	if !found2 {
		t.Errorf("expected vault path %q in config", vaultPath2)
	}
}

func TestInitConfig_AllFlagsCombined(t *testing.T) {
	// Test flags that don't require GPG operations (--login tested separately in e2e)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault.yaml")
	customGPGPath := "/usr/local/bin/gpg"

	// Run init config with flags (excluding --login which requires real GPG)
	_, stderr, err := runCmd("init", "config",
		"-c", configPath,
		"-v", vaultPath,
		"--gpg-program", customGPGPath,
	)
	if err != nil {
		t.Fatalf("init config with flags failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify settings
	cfg := loadConfigForTest(t, configPath)

	if cfg.GPG.Program != customGPGPath {
		t.Errorf("expected gpg.program=%q, got %q", customGPGPath, cfg.GPG.Program)
	}
	if len(cfg.Vault) != 1 || cfg.Vault[0] != vaultPath {
		t.Errorf("expected vault=[%q], got %v", vaultPath, cfg.Vault)
	}

	// Verify behavior section exists with defaults
	if cfg.Behavior.RequireExplicitVaultUpgrade == nil || *cfg.Behavior.RequireExplicitVaultUpgrade != false {
		t.Errorf("expected require_explicit_vault_upgrade=false")
	}
}

func TestInitConfig_HasDefaultAlgorithms(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Run init config
	_, stderr, err := runCmd("init", "config", "-c", configPath, "--no-gpg-program")
	if err != nil {
		t.Fatalf("init config failed: %v\nSTDERR: %s", err, stderr)
	}

	// Verify FIPS-compliant algorithms are present
	cfg := loadConfigForTest(t, configPath)
	if len(cfg.ApprovedAlgorithms) == 0 {
		t.Errorf("expected approved_algorithms to be set")
	}

	// Check for expected algorithms (RSA, ECC, EdDSA)
	hasRSA, hasECC, hasEdDSA := false, false, false
	for _, alg := range cfg.ApprovedAlgorithms {
		switch alg.Algo {
		case "RSA":
			hasRSA = true
			if alg.MinBits < 2048 {
				t.Errorf("RSA min_bits should be >= 2048, got %d", alg.MinBits)
			}
		case "ECC":
			hasECC = true
		case "EdDSA":
			hasEdDSA = true
		}
	}
	if !hasRSA {
		t.Errorf("expected RSA in approved_algorithms")
	}
	if !hasECC {
		t.Errorf("expected ECC in approved_algorithms")
	}
	if !hasEdDSA {
		t.Errorf("expected EdDSA in approved_algorithms")
	}
}
