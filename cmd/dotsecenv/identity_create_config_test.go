package main_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// identity create fell back to the built-in default config whenever normal
// startup failed for any reason, so a malformed config was silently ignored
// and its approved_algorithms did not apply. Only a missing config may use
// the defaults.
func TestIdentityCreate_MalformedConfigFails(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	valid := `approved_algorithms:
  - algo: ECC
    curves:
      - P-521
    min_bits: 521
vault:
  - ` + filepath.Join(tmpDir, "vault") + `
gpg:
  program: PATH
`
	if err := os.WriteFile(configPath, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-c", configPath, "identity", "create", "--algo", "P384", "--template", "--name", "X", "--email", "x@example.com"}

	_, stderr, err := runCmd(args...)
	if got := exitCode(t, err); got != 9 {
		t.Fatalf("P384 with a P-521-only config: exit %d, want 9 (algorithm not allowed)\nstderr: %s", got, stderr)
	}

	if err := os.WriteFile(configPath, []byte(valid+"approved_algorithms: [oops\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := runCmd(args...)
	if got := exitCode(t, err); got != 2 {
		t.Fatalf("malformed config: exit %d, want 2 (config error)\nstdout: %s\nstderr: %s", got, stdout, stderr)
	}
}

// With no config file at all, identity create still works from the defaults.
func TestIdentityCreate_MissingConfigUsesDefaults(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "missing.yaml")
	_, stderr, err := runCmd("-c", configPath, "identity", "create", "--algo", "P384", "--template", "--name", "X", "--email", "x@example.com")
	if err != nil {
		t.Fatalf("identity create without a config: %v\nstderr: %s", err, stderr)
	}
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("command did not run: %v", err)
	}
	return exitErr.ExitCode()
}
