package main_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var binaryPath string

func TestMain(m *testing.M) {
	// Build the binary once for all tests
	tmpDir, err := os.MkdirTemp("", "dotsecenv-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	binaryPath = filepath.Join(tmpDir, "dotsecenv")

	// Build command
	// We assume we are in the root of the repo or package dir
	// Tests run in the package directory
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if output, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build binary: %v\n%s\n", err, output)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// filteredEnv returns os.Environ() without DOTSECENV_CONFIG and DOTSECENV_FINGERPRINT
// to avoid test pollution
func filteredEnv() []string {
	baseEnv := os.Environ()
	filtered := make([]string, 0, len(baseEnv))
	for _, e := range baseEnv {
		if !strings.HasPrefix(e, "DOTSECENV_CONFIG=") && !strings.HasPrefix(e, "DOTSECENV_FINGERPRINT=") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func runCmd(args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = filteredEnv()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runCmdWithEnv(env []string, args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = append(filteredEnv(), env...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestGlobalOptions_ConfigPath(t *testing.T) {
	tmpDir := t.TempDir()

	// 2. Create a dummy vault (so validate works)
	vaultPath := filepath.Join(tmpDir, ".dotsecenv/vault")
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0700); err != nil {
		t.Fatal(err)
	}

	// 1. Create a dummy config file
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
gpg:
  program: PATH
`, vaultPath)), 0600)
	if err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	// Initialize vault using the tool itself to ensure validity
	_, _, err = runCmd("init", "vault", "-v", vaultPath)
	if err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	// Test cases for flag placement
	// Using 'validate' command as it reads config

	// Change working directory to temp dir so relative paths work if needed,
	// but we use absolute paths for flags to be safe.

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "flag before command",
			args: []string{"-c", configPath, "validate"},
		},
		{
			name: "flag after command",
			args: []string{"validate", "-c", configPath},
		},
		{
			name: "flag after command with other flags",
			// We can't easily test this without a command that takes other flags and validates config
			// validate takes --fix. Let's try that.
			args: []string{"validate", "--fix", "-c", configPath},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runCmd(tc.args...)
			if err != nil {
				t.Fatalf("command failed: %v\nSTDERR: %s", err, stderr)
			}

			// Check if it actually used the config
			// Validate prints "Configuration file: <path>"
			if !strings.Contains(stdout, configPath) {
				t.Errorf("expected output to contain config path %s, got:\n%s", configPath, stdout)
			}
		})
	}
}

func TestGlobalOptions_VaultOverride(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config pointing to vault A
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultAPath := filepath.Join(tmpDir, "vaultA")
	vaultBPath := filepath.Join(tmpDir, "vaultB")

	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
gpg:
  program: PATH
`, vaultAPath)), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize both vaults
	_, _, _ = runCmd("init", "vault", "-v", vaultAPath)
	_, _, _ = runCmd("init", "vault", "-v", vaultBPath)

	// Test 1: -c and -v together
	// Should use config settings but vault B
	// validate command prints loaded vaults

	args := []string{"-c", configPath, "validate", "-v", vaultBPath}
	stdout, stderr, err := runCmd(args...)
	if err != nil {
		t.Fatalf("command failed: %v\nSTDERR: %s\nSTDOUT: %s", err, stderr, stdout)
	}

	// Check stdout for vault B (should be present)
	if !strings.Contains(stdout, vaultBPath) {
		t.Errorf("expected stdout to contain vault B path %s, got:\n%s", vaultBPath, stdout)
	}
	// Check stdout for vault A (should NOT be present as loaded vault)
	// Note: Validate might verify config file existence, but "Vault 1: ..." section should be vault B
	if strings.Contains(stdout, fmt.Sprintf("Vault 1: %s", vaultAPath)) {
		t.Errorf("expected stdout NOT to show vault A as Vault 1, got:\n%s", stdout)
	}

	// Check stderr for warning
	if !strings.Contains(stderr, "warning: ignoring vaults in configuration") {
		t.Errorf("expected stderr to contain warning about ignoring config vaults, got:\n%s", stderr)
	}
}

func TestGlobalOptions_Silent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
gpg:
  program: PATH
`, vaultPath)), 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = runCmd("init", "vault", "-v", vaultPath)

	// Test: -c, -v and -s
	// Should use vault override but suppress warning
	args := []string{"-c", configPath, "-s", "validate", "-v", vaultPath}
	stdout, stderr, err := runCmd(args...)
	if err != nil {
		t.Fatalf("command failed: %v\nSTDERR: %s\nSTDOUT: %s", err, stderr, stdout)
	}

	if strings.Contains(stderr, "warning:") {
		t.Errorf("expected no warnings in silent mode, got:\n%s", stderr)
	}
}

func TestGlobalOptions_MixedPositions(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	err := os.WriteFile(configPath, []byte(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - default_vault
gpg:
  program: PATH
`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _ = runCmd("init", "vault", "-v", vaultPath)

	// Test: dotsecenv validate -c conf -v vault
	// Note: "secret store" reads secret from stdin usually, but we can pipe it
	// However, "secret store" requires a login/fingerprint usually.
	// "validate" is easier to test without extensive setup.
	// Let's use "validate" with mixed flags.

	// "dotsecenv validate -c conf -v vault"
	args := []string{"validate", "-c", configPath, "-v", vaultPath}
	stdout, stderr, err := runCmd(args...)
	if err != nil {
		t.Fatalf("command failed: %v\nSTDERR: %s\nSTDOUT: %s", err, stderr, stdout)
	}
	if !strings.Contains(stdout, vaultPath) {
		t.Errorf("expected to find vault path in output")
	}
	if !strings.Contains(stdout, configPath) {
		t.Errorf("expected to find config path in output")
	}
}

// TestSecretGet_ListMode tests "dotsecenv secret get" without arguments (list mode)
func TestSecretGet_ListMode(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
gpg:
  program: PATH
`, vaultPath)), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize vault
	_, stderr, err := runCmd("init", "vault", "-v", vaultPath)
	if err != nil {
		t.Fatalf("failed to init vault: %v, stderr: %s", err, stderr)
	}

	// Test: secret get (no args) - should list secrets (empty)
	stdout, stderr, err := runCmd("-c", configPath, "secret", "get")
	if err != nil {
		t.Fatalf("command failed: %v\nSTDERR: %s", err, stderr)
	}

	// Should say "No secrets found" for empty vault
	if !strings.Contains(stdout, "No secrets found") {
		t.Errorf("expected 'No secrets found' for empty vault, got: %s", stdout)
	}
}

// TestSecretGet_ListModeJSON tests "dotsecenv secret get --json" without arguments
func TestSecretGet_ListModeJSON(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
gpg:
  program: PATH
`, vaultPath)), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize vault
	_, stderr, err := runCmd("init", "vault", "-v", vaultPath)
	if err != nil {
		t.Fatalf("failed to init vault: %v, stderr: %s", err, stderr)
	}

	// Test: secret get --json (no args) - should return empty JSON array
	stdout, stderr, err := runCmd("-c", configPath, "secret", "get", "--json")
	if err != nil {
		t.Fatalf("command failed: %v\nSTDERR: %s", err, stderr)
	}

	// Should be empty JSON array for empty vault
	trimmed := strings.TrimSpace(stdout)
	if trimmed != "[]" && trimmed != "null" {
		t.Errorf("expected empty JSON array for empty vault, got: %s", stdout)
	}
}

// TestSecretGet_ListModeWithVault tests "dotsecenv secret get -v N" without secret key
func TestSecretGet_ListModeWithVault(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vault1Path := filepath.Join(tmpDir, "vault1")
	vault2Path := filepath.Join(tmpDir, "vault2")

	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
  - %s
gpg:
  program: PATH
`, vault1Path, vault2Path)), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize both vaults
	_, stderr, err := runCmd("init", "vault", "-v", vault1Path)
	if err != nil {
		t.Fatalf("failed to init vault1: %v, stderr: %s", err, stderr)
	}
	_, stderr, err = runCmd("init", "vault", "-v", vault2Path)
	if err != nil {
		t.Fatalf("failed to init vault2: %v, stderr: %s", err, stderr)
	}

	// Test: secret get -v 1 (no args) - should list secrets from vault 1
	stdout, stderr, err := runCmd("-c", configPath, "secret", "get", "-v", "1")
	if err != nil {
		t.Fatalf("command failed: %v\nSTDERR: %s", err, stderr)
	}

	// Should say "No secrets found" for empty vault
	if !strings.Contains(stdout, "No secrets found") {
		t.Errorf("expected 'No secrets found' for empty vault, got: %s", stdout)
	}
}

// TestSecretGet_ListModeErrorFlags tests that --all and --last require a secret key
func TestSecretGet_ListModeErrorFlags(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	err := os.WriteFile(configPath, []byte(fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - %s
gpg:
  program: PATH
`, vaultPath)), 0600)
	if err != nil {
		t.Fatal(err)
	}

	// Initialize vault
	_, stderr, err := runCmd("init", "vault", "-v", vaultPath)
	if err != nil {
		t.Fatalf("failed to init vault: %v, stderr: %s", err, stderr)
	}

	// Test: secret get --all (no args) - should error
	_, stderr, err = runCmd("-c", configPath, "secret", "get", "--all")
	if err == nil {
		t.Error("expected error for 'secret get --all' without secret key")
	}
	if !strings.Contains(stderr, "--all flag requires a secret key") {
		t.Errorf("expected '--all flag requires a secret key' error, got: %s", stderr)
	}

	// Test: secret get --last (no args) - should error
	_, stderr, err = runCmd("-c", configPath, "secret", "get", "--last")
	if err == nil {
		t.Error("expected error for 'secret get --last' without secret key")
	}
	if !strings.Contains(stderr, "--last flag requires a secret key") {
		t.Errorf("expected '--last flag requires a secret key' error, got: %s", stderr)
	}
}
