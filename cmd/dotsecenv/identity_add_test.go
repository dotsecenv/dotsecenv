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
Name-Real: Test User 3
Name-Email: test3@dotsecenv.com
Expire-Date: 0
%no-protection
%commit
`
	if err := os.WriteFile(paramsPath, []byte(params), 0o600); err != nil {
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
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
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
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
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

	// Add to vault A again using -v 1 (since A already has it, should succeed with "already present" message)
	argsDefault := []string{"-c", configPath, "vault", "identity", "add", "-v", "1", fingerprint}
	stdoutDefault, _, errDefault := runCmdWithEnv(env, argsDefault...)

	// Should NOT error in non-strict mode when identity already exists
	if errDefault != nil {
		t.Errorf("expected success when identity already exists (non-strict mode), got error: %v", errDefault)
	}
	// Status is printed to stdout
	if !strings.Contains(stdoutDefault, "skipped, already present") {
		t.Errorf("expected 'skipped, already present' in output, got: %s", stdoutDefault)
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
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
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
`), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", vaultPath)

	// Add identity with -v (not in config) -> Should succeed because -v explicitly loads the vault
	args := []string{"-c", configPath, "vault", "identity", "add", "-v", vaultPath, fingerprint}
	stdout, stderr, err := runCmdWithEnv(env, args...)
	if err != nil {
		t.Fatalf("vault identity add failed: %v\nSTDERR: %s\nSTDOUT: %s", err, stderr, stdout)
	}

	// Verify the identity was added by listing it
	listArgs := []string{"-c", configPath, "vault", "identity", "list", "-v", vaultPath}
	listOut, _, _ := runCmdWithEnv(env, listArgs...)
	if !strings.Contains(listOut, fingerprint) {
		t.Errorf("expected identity in vault, got: %s", listOut)
	}
}

func TestIdentityAdd_StrictModeFailsOnParseError(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	validVaultPath := filepath.Join(tmpDir, "valid_vault")
	corruptVaultPath := filepath.Join(tmpDir, "corrupt_vault")

	// Config with strict: true and two vaults (gpg.program required in strict mode)
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
strict: true
gpg:
  program: "%s"
`, validVaultPath, corruptVaultPath, gpgPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	// Init only the valid vault
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", validVaultPath)

	// Create a corrupt vault file with valid header marker but invalid JSON
	corruptContent := `# === VAULT HEADER v1 ===
{"version":1,"identities":[],"secrets":{invalid json here}
# === VAULT DATA ===
`
	if err := os.WriteFile(corruptVaultPath, []byte(corruptContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Try to add identity in strict mode with --all
	args := []string{"-c", configPath, "vault", "identity", "add", fingerprint, "--all"}
	stdout, stderr, err := runCmdWithEnv(env, args...)

	// Should fail in strict mode due to corrupt vault
	if err == nil {
		t.Fatalf("expected error in strict mode with corrupt vault, but succeeded\nSTDOUT: %s\nSTDERR: %s", stdout, stderr)
	}

	// Should show the strict mode error message
	if !strings.Contains(stdout, "Strict mode: vault errors detected") {
		t.Errorf("expected 'Strict mode: vault errors detected' in output, got:\nSTDOUT: %s\nSTDERR: %s", stdout, stderr)
	}

	// Should show which vault has the error
	if !strings.Contains(stdout, "Vault 2") || !strings.Contains(stdout, "error") {
		t.Errorf("expected error message for Vault 2, got:\nSTDOUT: %s", stdout)
	}

	// Should show what would have been done for valid vault
	if !strings.Contains(stdout, "would add identity") {
		t.Errorf("expected 'would add identity' for valid vault, got:\nSTDOUT: %s", stdout)
	}

	// Verify the identity was NOT added to the valid vault
	listArgs := []string{"-c", configPath, "vault", "identity", "list", "-v", validVaultPath}
	listOut, _, _ := runCmdWithEnv(env, listArgs...)
	if strings.Contains(listOut, fingerprint) {
		t.Errorf("identity should NOT have been added in strict mode when another vault has errors")
	}
}

func TestIdentityAdd_NonStrictModeContinuesOnParseError(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	validVaultPath := filepath.Join(tmpDir, "valid_vault")
	corruptVaultPath := filepath.Join(tmpDir, "corrupt_vault")

	// Config with strict: false (default) and two vaults
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
strict: false
`, validVaultPath, corruptVaultPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	// Init only the valid vault
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", validVaultPath)

	// Create a corrupt vault file with valid header marker but invalid JSON
	corruptContent := `# === VAULT HEADER v1 ===
{"version":1,"identities":[],"secrets":{invalid json here}
# === VAULT DATA ===
`
	if err := os.WriteFile(corruptVaultPath, []byte(corruptContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Add identity in non-strict mode with --all
	args := []string{"-c", configPath, "vault", "identity", "add", fingerprint, "--all"}
	stdout, stderr, err := runCmdWithEnv(env, args...)

	// Should succeed in non-strict mode (adds to valid vault, skips corrupt)
	if err != nil {
		t.Fatalf("expected success in non-strict mode, got error: %v\nSTDOUT: %s\nSTDERR: %s", err, stdout, stderr)
	}

	// Should show that valid vault was added
	if !strings.Contains(stdout, "added") {
		t.Errorf("expected 'added' for valid vault, got:\nSTDOUT: %s", stdout)
	}

	// Should show that corrupt vault was skipped
	if !strings.Contains(stdout, "skipped") {
		t.Errorf("expected 'skipped' for corrupt vault, got:\nSTDOUT: %s", stdout)
	}

	// Verify the identity WAS added to the valid vault
	listArgs := []string{"-c", configPath, "vault", "identity", "list", "-v", validVaultPath}
	listOut, _, _ := runCmdWithEnv(env, listArgs...)
	if !strings.Contains(listOut, fingerprint) {
		t.Errorf("identity should have been added to valid vault in non-strict mode")
	}
}

func TestIdentityAdd_AutoSelectSingleVault(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	validVaultPath := filepath.Join(tmpDir, "valid_vault")
	missingVaultPath := filepath.Join(tmpDir, "missing_vault") // Does not exist

	// Config with two vaults: one valid, one missing (not corrupt, just doesn't exist)
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
`, validVaultPath, missingVaultPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	// Init only the valid vault (leave missing_vault non-existent)
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", validVaultPath)

	// Add identity without specifying vault - should auto-select the only available vault
	args := []string{"-c", configPath, "vault", "identity", "add", fingerprint}
	stdout, stderr, err := runCmdWithEnv(env, args...)

	// Should succeed with auto-selection
	if err != nil {
		t.Fatalf("expected success with auto-selection, got error: %v\nSTDOUT: %s\nSTDERR: %s", err, stdout, stderr)
	}

	// Should NOT prompt for selection (prompt text is "Select target vault for identity:")
	if strings.Contains(stdout, "Select target vault") || strings.Contains(stderr, "Select target vault") {
		t.Errorf("should not prompt for selection when only one vault is available\nSTDOUT: %s\nSTDERR: %s", stdout, stderr)
	}

	// Should show that vault was added
	if !strings.Contains(stdout, "added") {
		t.Errorf("expected 'added' in output, got:\nSTDOUT: %s", stdout)
	}

	// Verify the identity was added
	listArgs := []string{"-c", configPath, "vault", "identity", "list", "-v", validVaultPath}
	listOut, _, _ := runCmdWithEnv(env, listArgs...)
	if !strings.Contains(listOut, fingerprint) {
		t.Errorf("identity should have been added to the auto-selected vault")
	}
}

func TestIdentityAdd_StrictModeShowsFailingVaultNumbers(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, fingerprint := setupGPG(t)
	defer func() { _ = os.RemoveAll(gpgHome) }()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	corrupt1Path := filepath.Join(tmpDir, "corrupt1")
	validVaultPath := filepath.Join(tmpDir, "valid_vault")
	corrupt2Path := filepath.Join(tmpDir, "corrupt2")

	// Config with strict: true and three vaults: corrupt, valid, corrupt
	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
  - "%s"
strict: true
gpg:
  program: "%s"
`, corrupt1Path, validVaultPath, corrupt2Path, gpgPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fingerprint,
	}

	// Init valid vault first
	_, _, _ = runCmdWithEnv(env, "init", "vault", "-v", validVaultPath)

	// Create corrupt vaults with valid header marker but invalid JSON
	corruptContent := `# === VAULT HEADER v1 ===
{"version":1,"identities":[],"secrets":{invalid json}
# === VAULT DATA ===
`
	if err := os.WriteFile(corrupt1Path, []byte(corruptContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corrupt2Path, []byte(corruptContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Try to add identity in strict mode with --all
	args := []string{"-c", configPath, "vault", "identity", "add", fingerprint, "--all"}
	stdout, _, err := runCmdWithEnv(env, args...)

	// Should fail
	if err == nil {
		t.Fatal("expected error in strict mode")
	}

	// Should show specific vault numbers in the skip message (vaults 1, 3)
	if !strings.Contains(stdout, "vaults 1, 3") {
		t.Errorf("expected 'vaults 1, 3' in skip message, got:\nSTDOUT: %s", stdout)
	}
}
