package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runCmdWithEnv(env []string, args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(filteredEnv(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func setupGPG(t *testing.T) (string, string) {
	gpgHome, err := os.MkdirTemp("", "dotsecenv-test-gpg")
	if err != nil {
		t.Fatal(err)
	}

	// Generate a key
	paramsPath := filepath.Join(gpgHome, "params")
	params := `
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: encrypt
Name-Real: Test User
Name-Email: test@example.com
Expire-Date: 0
%no-protection
%commit
`
	if err := os.WriteFile(paramsPath, []byte(params), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("gpg", "--batch", "--generate-key", paramsPath)
	cmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to generate gpg key: %v\n%s", err, out)
	}

	// Get fingerprint
	cmd = exec.Command("gpg", "--list-keys", "--with-colons")
	cmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to list keys: %v", err)
	}

	lines := strings.Split(string(out), "\n")
	var fingerprint string
	for _, line := range lines {
		if strings.HasPrefix(line, "fpr:") {
			parts := strings.Split(line, ":")
			if len(parts) > 9 {
				fingerprint = parts[9]
				break
			}
		}
	}

	if fingerprint == "" {
		t.Fatal("failed to find fingerprint")
	}

	return gpgHome, fingerprint
}

func TestIdentityAdd_All(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultAPath := filepath.Join(tmpDir, "vaultA")
	vaultBPath := filepath.Join(tmpDir, "vaultB")

	// Updated config format: list of paths strings
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
`, vaultAPath, vaultBPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("Config content:\n%s", configContent)

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint, // For signing
	}

	// Init vaults (creates empty vaults)
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", vaultAPath)
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", vaultBPath)

	// Add identity to ALL vaults
	// vault identity add FP --all
	args := []string{"-c", configPath, "vault", "identity", "add", fingerprint, "--all"}
	stdout, stderr, err := runCmdWithEnv(env, args...)
	if err != nil {
		t.Fatalf("vault identity add --all FAILED (test): %v\nSTDERR: %s\nSTDOUT: %s", err, stderr, stdout)
	}
	t.Logf("vault identity add --all output:\nSTDERR: %s\nSTDOUT: %s", stderr, stdout)

	// Verify identity is in Vault A (index 1)
	// We can use -v 1
	argsA := []string{"-c", configPath, "vault", "identity", "list", "-v", vaultAPath}
	stdoutA, stderrA, errA := runCmdWithEnv(env, argsA...)
	if errA != nil {
		t.Fatalf("list vault A failed: %v\nSTDERR: %s", errA, stderrA)
	}
	if !strings.Contains(stdoutA, fingerprint) {
		t.Errorf("expected identity in vault A")
	}

	// Verify identity is in Vault B (index 2)
	argsB := []string{"-c", configPath, "vault", "identity", "list", "-v", vaultBPath}
	stdoutB, stderrB, errB := runCmdWithEnv(env, argsB...)
	if errB != nil {
		t.Fatalf("list vault B failed: %v\nSTDERR: %s", errB, stderrB)
	}
	if !strings.Contains(stdoutB, fingerprint) {
		t.Errorf("expected identity in vault B")
	}
}

func TestIdentityAdd_SingleVault(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultAPath := filepath.Join(tmpDir, "vaultA")
	vaultBPath := filepath.Join(tmpDir, "vaultB")

	// Updated config format: list of paths strings
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
`, vaultAPath, vaultBPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	// Init vaults
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", vaultAPath)
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", vaultBPath)

	// Add identity to Vault A ONLY (using -v PATH)
	args := []string{"-c", configPath, "vault", "identity", "add", "-v", vaultAPath, fingerprint}
	stdout, stderr, err := runCmdWithEnv(env, args...)
	if err != nil {
		t.Fatalf("vault identity add -v failed: %v\nSTDERR: %s\nSTDOUT: %s", err, stderr, stdout)
	}

	// Verify in A
	stdoutA, _, _ := runCmdWithEnv(env, "-c", configPath, "vault", "identity", "list", "-v", vaultAPath)
	if !strings.Contains(stdoutA, fingerprint) {
		t.Errorf("expected identity in vault A")
	}

	// Verify NOT in B
	stdoutB, _, _ := runCmdWithEnv(env, "-c", configPath, "vault", "identity", "list", "-v", vaultBPath)
	if strings.Contains(stdoutB, fingerprint) {
		t.Errorf("expected identity NOT in vault B")
	}

	// Add to default (should be top vault = A)
	// Since A already has it, it should fail/warn about already existing
	argsDefault := []string{"-c", configPath, "vault", "identity", "add", fingerprint}
	_, stderrDefault, errDefault := runCmdWithEnv(env, argsDefault...)

	if errDefault == nil {
		t.Errorf("expected error when adding existing identity to default vault")
	}
	if !strings.Contains(stderrDefault, "already exists") {
		t.Errorf("expected 'already exists' error, got: %s", stderrDefault)
	}
}

func TestIdentityAdd_MissingVault(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "missing_vault")

	// Create a minimal config (vault path doesn't need to exist for this test)
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
`, vaultPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	// Test -v with missing file -> Should Error
	args := []string{"-c", configPath, "vault", "identity", "add", "-v", vaultPath, fingerprint}
	_, stderr, err := runCmdWithEnv(env, args...)
	if err == nil {
		t.Errorf("expected error for missing vault file with -v")
	}
	if !strings.Contains(stderr, "vault file not found") && !strings.Contains(stderr, "no vault files could be opened") && !strings.Contains(stderr, "does not exist") {
		t.Errorf("expected error message about missing vault, got: %s", stderr)
	}
}

func TestIdentityAdd_UnconfiguredVault(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "extra_vault")

	if err := os.WriteFile(configPath, []byte(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault: []
`), 0600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", vaultPath)

	// Add identity with -v (not in config) -> Should Warn
	args := []string{"-c", configPath, "vault", "identity", "add", "-v", vaultPath, fingerprint}
	_, stderr, err := runCmdWithEnv(env, args...)
	if err != nil {
		t.Fatalf("vault identity add failed: %v\nSTDERR: %s", err, stderr)
	}

	if !strings.Contains(stderr, "warning: vault path") || !strings.Contains(stderr, "not in configuration") {
		t.Errorf("expected warning about unconfigured vault, got: %s", stderr)
	}
}
