package main_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// vault compact used to rewrite the vault in CI without --yes, and to ask in a
// terminal. It now writes only with --yes; without it, it reports the plan,
// leaves the vault alone and exits 10.
func TestVaultCompact_WritesOnlyWithYes(t *testing.T) {
	gpgHome, err := os.MkdirTemp("", "dse-gpg") // short path for the agent socket
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(gpgHome) })
	t.Cleanup(startGPGAgent(t, gpgHome))
	fp := generateKey(t, gpgHome, "Compact User", "compact@example.com")

	vaultPath := filepath.Join(t.TempDir(), "vault")
	configPath := writeUserConfig(t, vaultPath)
	env := []string{"GNUPGHOME=" + gpgHome}
	loginUser(t, env, configPath, fp)
	if _, stderr, err := runCmdWithEnv(env, "-c", configPath, "init", "vault", "-v", vaultPath); err != nil {
		t.Fatalf("init vault: %v\n%s", err, stderr)
	}
	for _, value := range []string{"one", "two", "three"} {
		cmd := exec.Command(binaryPath, "-c", configPath, "secret", "store", "KEY", "--no-share")
		cmd.Env = append(filteredEnv(), env...)
		cmd.Stdin = strings.NewReader(value)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("secret store: %v\n%s", err, out)
		}
	}

	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	ciEnv := append([]string{"CI=true"}, env...)
	for _, args := range [][]string{{"vault", "compact"}, {"vault", "compact", "--json"}} {
		stdout, stderr, err := runCmdWithEnv(ciEnv, append([]string{"-c", configPath}, args...)...)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 10 {
			t.Fatalf("%v without --yes: want exit 10, got %v\nstdout: %s\nstderr: %s", args, err, stdout, stderr)
		}
		after, _ := os.ReadFile(vaultPath)
		if !bytes.Equal(before, after) {
			t.Fatalf("%v without --yes rewrote the vault", args)
		}
		if len(args) == 2 && !strings.Contains(stdout, "Run: dotsecenv vault compact --yes -c '"+configPath+"' -v '"+vaultPath+"'") {
			t.Errorf("text output should print the --yes command, got:\n%s", stdout)
		}
	}

	if stdout, stderr, err := runCmdWithEnv(ciEnv, "-c", configPath, "vault", "compact", "--yes"); err != nil {
		t.Fatalf("vault compact --yes: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	after, _ := os.ReadFile(vaultPath)
	if bytes.Equal(before, after) {
		t.Fatal("vault compact --yes did not rewrite the vault")
	}

	if stdout, stderr, err := runCmdWithEnv(ciEnv, "-c", configPath, "vault", "compact"); err != nil {
		t.Errorf("compact on an already compact vault: want exit 0, got %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
}
