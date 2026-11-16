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

// TestSecretShareRevoke_VaultPathTargetsThatVault checks that `-v <path>` on
// `secret share` and `secret revoke` acts on the vault at that path, not on
// the config's first vault.
func TestSecretShareRevoke_VaultPathTargetsThatVault(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}
	if _, err := exec.LookPath("gpg-agent"); err != nil {
		t.Skip("gpg-agent not found")
	}

	// Short path keeps the gpg-agent socket under the Unix socket length limit.
	gpgHome, err := os.MkdirTemp("/tmp", "gpg")
	if err != nil {
		gpgHome, err = os.MkdirTemp("", "gpg")
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() { _ = os.RemoveAll(gpgHome) }()

	cleanup := startGPGAgent(t, gpgHome)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fpA, err := generateKeyWithTimeout(ctx, t, gpgHome, "User A", "usera@example.com")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Skip("key generation timed out (5s)")
		}
		t.Fatalf("generate key A: %v", err)
	}
	fpB, err := generateKeyWithTimeout(ctx, t, gpgHome, "User B", "userb@example.com")
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Skip("key generation timed out (5s)")
		}
		t.Fatalf("generate key B: %v", err)
	}

	dir := t.TempDir()
	vault1 := filepath.Join(dir, "vault1")
	vault2 := filepath.Join(dir, "vault2")
	env := []string{"GNUPGHOME=" + gpgHome}

	writeConfig := func() string {
		p := filepath.Join(t.TempDir(), "config.yaml")
		content := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
  - "%s"
gpg:
  program: PATH
`, vault1, vault2)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	configA := writeConfig()
	configB := writeConfig()
	loginUser(t, env, configA, fpA)
	loginUser(t, env, configB, fpB)

	for _, v := range []string{vault1, vault2} {
		if _, stderr, err := runCmdWithEnv(env, "-c", configA, "init", "vault", "-v", v); err != nil {
			t.Fatalf("init vault %s: %v\n%s", v, err, stderr)
		}
	}

	// Store the secret only in the second vault.
	cmd := exec.Command(binaryPath, "-c", configA, "secret", "store", "SEC1", "-v", "2")
	cmd.Env = append(filteredEnv(), env...)
	cmd.Stdin = strings.NewReader("secret_value_1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("secret store: %v\n%s", err, out)
	}

	// Share by path into the second vault.
	stdout, stderr, err := runCmdWithEnv(env, "-c", configA, "secret", "share", "SEC1", fpB, "-v", vault2)
	if err != nil {
		t.Fatalf("secret share -v %s: %v\nstdout: %s\nstderr: %s", vault2, err, stdout, stderr)
	}
	if strings.Contains(stdout, "skipped") {
		t.Fatalf("secret share -v %s skipped the vault:\n%s", vault2, stdout)
	}

	stdout, stderr, err = runCmdWithEnv(env, "-c", configB, "secret", "get", "SEC1")
	if err != nil {
		t.Fatalf("secret get (B) after share: %v\n%s", err, stderr)
	}
	if strings.TrimSpace(stdout) != "secret_value_1" {
		t.Fatalf("unexpected value for B: %q", stdout)
	}

	// Revoke by path from the second vault.
	stdout, stderr, err = runCmdWithEnv(env, "-c", configA, "secret", "revoke", "SEC1", fpB, "-v", vault2)
	if err != nil {
		t.Fatalf("secret revoke -v %s: %v\nstdout: %s\nstderr: %s", vault2, err, stdout, stderr)
	}
	if strings.Contains(stdout, "skipped") {
		t.Fatalf("secret revoke -v %s skipped the vault:\n%s", vault2, stdout)
	}

	// A second revoke reports that B no longer has access in the second vault.
	stdout, stderr, err = runCmdWithEnv(env, "-c", configA, "secret", "revoke", "SEC1", fpB, "-v", vault2)
	if err != nil {
		t.Fatalf("second secret revoke: %v\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "target does not have access") || !strings.Contains(stdout, vault2) {
		t.Fatalf("expected second revoke to report no access in %s, got:\n%s", vault2, stdout)
	}
}
