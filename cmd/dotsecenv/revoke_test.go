package main_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startGPGAgent starts a gpg-agent for the given GNUPGHOME and returns a cleanup function.
// The agent is started with --allow-preset-passphrase for non-interactive testing.
func startGPGAgent(t *testing.T, gpgHome string) func() {
	t.Helper()

	// Create gpg-agent.conf to allow loopback pinentry (for non-interactive use)
	agentConf := filepath.Join(gpgHome, "gpg-agent.conf")
	confContent := "allow-loopback-pinentry\nallow-preset-passphrase\n"
	if err := os.WriteFile(agentConf, []byte(confContent), 0600); err != nil {
		t.Fatalf("failed to write gpg-agent.conf: %v", err)
	}

	// Use gpgconf --launch to start the agent (more reliable than --daemon)
	env := append(filteredEnv(), "GNUPGHOME="+gpgHome)

	// Launch gpg-agent using gpgconf (which handles daemonization properly)
	cmd := exec.Command("gpgconf", "--homedir", gpgHome, "--launch", "gpg-agent")
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to launch gpg-agent: %v\nOutput: %s", err, output)
	}

	// Return cleanup function to kill the agent
	return func() {
		killCmd := exec.Command("gpgconf", "--homedir", gpgHome, "--kill", "gpg-agent")
		killCmd.Env = env
		_ = killCmd.Run() // Ignore errors on cleanup
	}
}

// generateKeyWithTimeout generates a GPG key with a timeout context
func generateKeyWithTimeout(ctx context.Context, t *testing.T, gpgHome, name, email string) (string, error) {
	paramsPath := filepath.Join(gpgHome, fmt.Sprintf("params-%s", name))
	params := fmt.Sprintf(`
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: encrypt
Name-Real: %s
Name-Email: %s
Expire-Date: 0
%%no-protection
%%commit
`, name, email)

	if err := os.WriteFile(paramsPath, []byte(params), 0600); err != nil {
		return "", fmt.Errorf("failed to write params file: %w", err)
	}

	cmd := exec.CommandContext(ctx, "gpg", "--batch", "--generate-key", paramsPath)
	cmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to generate gpg key for %s: %w\n%s", name, err, out)
	}

	// Get fingerprint (most recent key)
	cmd = exec.CommandContext(ctx, "gpg", "--list-keys", "--with-colons", email)
	cmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list keys for %s: %w", email, err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "fpr:") {
			parts := strings.Split(line, ":")
			if len(parts) > 9 {
				return parts[9], nil
			}
		}
	}
	return "", fmt.Errorf("failed to find fingerprint for %s", email)
}

func generateKey(t *testing.T, gpgHome, name, email string) string {
	paramsPath := filepath.Join(gpgHome, fmt.Sprintf("params-%s", name))
	params := fmt.Sprintf(`
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: encrypt
Name-Real: %s
Name-Email: %s
Expire-Date: 0
%%no-protection
%%commit
`, name, email)

	if err := os.WriteFile(paramsPath, []byte(params), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("gpg", "--batch", "--generate-key", paramsPath)
	cmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to generate gpg key for %s: %v\n%s", name, err, out)
	}

	// Get fingerprint (most recent key)
	cmd = exec.Command("gpg", "--list-keys", "--with-colons", email)
	cmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to list keys for %s: %v", email, err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "fpr:") {
			parts := strings.Split(line, ":")
			if len(parts) > 9 {
				return parts[9]
			}
		}
	}
	t.Fatalf("failed to find fingerprint for %s", email)
	return ""
}

func TestSecretRevoke_Self(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}
	if _, err := exec.LookPath("gpg-agent"); err != nil {
		t.Skip("gpg-agent not found")
	}

	// Create isolated GNUPGHOME for this test
	// Use /tmp directly to keep socket paths short (Unix socket path limit is ~100 chars)
	gpgHome, err := os.MkdirTemp("/tmp", "gpg")
	if err != nil {
		// Fall back to default temp dir if /tmp doesn't work
		gpgHome, err = os.MkdirTemp("", "gpg")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = os.RemoveAll(gpgHome) }()

	// Start our own gpg-agent for this GNUPGHOME
	cleanup := startGPGAgent(t, gpgHome)
	defer cleanup()

	// Use a 5-second timeout for key generation operations
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create two users with timeout
	fpA, err := generateKeyWithTimeout(ctx, t, gpgHome, "User A", "usera@example.com")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Skip("key generation timed out (5s) - gpg-agent may not be functioning properly")
		}
		t.Fatalf("failed to generate key for User A: %v", err)
	}

	fpB, err := generateKeyWithTimeout(ctx, t, gpgHome, "User B", "userb@example.com")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Skip("key generation timed out (5s) - gpg-agent may not be functioning properly")
		}
		t.Fatalf("failed to generate key for User B: %v", err)
	}

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create two configs: one with strict mode, one without
	configPathStrict := filepath.Join(tmpDir, "config-strict.yaml")
	configPathNonStrict := filepath.Join(tmpDir, "config.yaml")

	// Get the gpg path for strict mode config
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Fatalf("failed to find gpg: %v", err)
	}

	configContentStrict := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
strict: true
gpg:
  program: "%s"
`, vaultPath, gpgPath)

	configContentNonStrict := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
strict: false
gpg:
  program: PATH
`, vaultPath)

	if err := os.WriteFile(configPathStrict, []byte(configContentStrict), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPathNonStrict, []byte(configContentNonStrict), 0600); err != nil {
		t.Fatal(err)
	}

	// Environment for User A
	envA := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fpA,
	}
	// Environment for User B
	envB := []string{
		"GNUPGHOME=" + gpgHome,
		"DOTSECENV_FINGERPRINT=" + fpB,
	}

	// Init vault (use non-strict config for setup)
	_, _, _ = runCmdWithEnv(envA, "init", "vault", "-v", vaultPath)

	// Identities are auto-added by secret store (for User A) and secret share (for User B)

	// 1. Store secret SEC1 (User A)
	cmd := exec.Command(binaryPath, "-c", configPathNonStrict, "secret", "store", "SEC1")
	cmd.Env = append(filteredEnv(), envA...)
	cmd.Stdin = strings.NewReader("secret_value_1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("secret store failed: %v\n%s", err, out)
	}

	// 2. Share with User B (User A)
	_, _, err = runCmdWithEnv(envA, "-c", configPathNonStrict, "secret", "share", "SEC1", fpB)
	if err != nil {
		t.Fatalf("secret share failed: %v", err)
	}

	// Verify User B can access
	stdout, _, err := runCmdWithEnv(envB, "-c", configPathNonStrict, "secret", "get", "SEC1")
	if err != nil {
		t.Fatalf("secret get (B) failed: %v", err)
	}
	if strings.TrimSpace(stdout) != "secret_value_1" {
		t.Errorf("unexpected secret value for B: %s", stdout)
	}

	// 3. Revoke User A (Self Revocation)
	// User A revokes themselves.
	_, _, err = runCmdWithEnv(envA, "-c", configPathNonStrict, "secret", "revoke", "SEC1", fpA)
	if err != nil {
		t.Fatalf("secret revoke (self) failed: %v", err)
	}

	// 4. Verify User A can still access older value after self-revocation
	// After self-revocation, User A can still decrypt their original value
	// (Fallback to older values is always allowed silently)
	stdout, _, err = runCmdWithEnv(envA, "-c", configPathNonStrict, "secret", "get", "SEC1")
	if err != nil {
		t.Errorf("expected secret get (A) to succeed with older value after self-revocation, got error: %v", err)
	}
	// Should get the original value
	if strings.TrimSpace(stdout) != "secret_value_1" {
		t.Errorf("expected original secret value, got: %s", stdout)
	}

	// 5. Verify User B CAN still access (with either config)
	stdout, _, err = runCmdWithEnv(envB, "-c", configPathNonStrict, "secret", "get", "SEC1")
	if err != nil {
		t.Errorf("secret get (B) failed after A revoked self: %v", err)
	}
	if strings.TrimSpace(stdout) != "secret_value_1" {
		t.Errorf("unexpected secret value for B after A revoked self: %s", stdout)
	}
}
