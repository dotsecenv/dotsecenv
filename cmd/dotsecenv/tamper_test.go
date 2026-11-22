package main_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tamperLatestValue replaces the ciphertext of key's last value line with an
// encryption of plaintext to fp, leaving its hash and signature as they were.
func tamperLatestValue(t *testing.T, env []string, vaultPath, key, plaintext, fp string) {
	t.Helper()
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	last := -1
	var oldValue string
	for i, line := range lines {
		var e struct {
			Type   string `json:"type"`
			Secret string `json:"secret"`
			Data   struct {
				Value string `json:"value"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.Type == "value" && e.Secret == key {
			last, oldValue = i, e.Data.Value
		}
	}
	if last < 0 {
		t.Fatalf("no value line for %s", key)
	}

	cmd := exec.Command("gpg", "--batch", "--armor", "--trust-model", "always", "--encrypt", "-r", fp)
	cmd.Env = append(filteredEnv(), env...)
	cmd.Stdin = strings.NewReader(plaintext)
	armored, err := cmd.Output()
	if err != nil {
		t.Fatalf("gpg encrypt: %v", err)
	}
	lines[last] = strings.Replace(lines[last], oldValue, base64.StdEncoding.EncodeToString(armored), 1)
	if err := os.WriteFile(vaultPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
}

// vaultUser runs dotsecenv as one logged-in user of a single shared vault.
type vaultUser struct {
	fp     string
	config string
	env    []string
}

func (u vaultUser) run(stdin string, args ...string) (string, string, error) {
	cmd := exec.Command(binaryPath, append([]string{"-c", u.config}, args...)...)
	cmd.Env = append(filteredEnv(), u.env...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// setupSharedVault creates one key per name in a fresh GNUPGHOME, logs each
// in, and initializes a vault. It returns the vault path and the users.
func setupSharedVault(t *testing.T, names ...string) (string, []vaultUser) {
	t.Helper()
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
	t.Cleanup(func() { _ = os.RemoveAll(gpgHome) })
	t.Cleanup(startGPGAgent(t, gpgHome))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	vaultPath := filepath.Join(t.TempDir(), "vault")
	env := []string{"GNUPGHOME=" + gpgHome}
	var users []vaultUser
	for _, name := range names {
		fp, err := generateKeyWithTimeout(ctx, t, gpgHome, name, strings.ToLower(name)+"@example.com")
		if err != nil {
			t.Fatalf("generate key %s: %v", name, err)
		}
		config := writeUserConfig(t, vaultPath)
		loginUser(t, env, config, fp)
		users = append(users, vaultUser{fp: fp, config: config, env: env})
	}
	if _, stderr, err := users[0].run("", "init", "vault", "-v", vaultPath); err != nil {
		t.Fatalf("init vault: %v\n%s", err, stderr)
	}
	return vaultPath, users
}

// TestTamperedValue_RefusedBeforeDecrypt checks that get, share and revoke
// refuse a value whose ciphertext no longer matches its hash and signature.
func TestTamperedValue_RefusedBeforeDecrypt(t *testing.T) {
	vaultPath, users := setupSharedVault(t, "UserA", "UserB")
	run, fpA, fpB, env := users[0].run, users[0].fp, users[1].fp, users[0].env

	for _, args := range [][]string{
		{"secret", "store", "DB_URL"},
		{"secret", "store", "OTHER"},
	} {
		if _, stderr, err := run("real-value", args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, stderr)
		}
	}
	if _, stderr, err := run("", "secret", "share", "DB_URL", fpB); err != nil {
		t.Fatalf("share: %v\n%s", err, stderr)
	}

	tamperLatestValue(t, env, vaultPath, "DB_URL", "attacker-value", fpA)
	tamperLatestValue(t, env, vaultPath, "OTHER", "attacker-value", fpA)
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"secret", "get", "DB_URL"},
		{"secret", "get", "DB_URL", "--all"},
		{"secret", "get", "DB_URL", "--last"},
		{"secret", "get", "DB_URL", "-v", "1"},
		{"secret", "get", "DB_URL", "--json"},
		{"secret", "share", "OTHER", fpB},
		{"secret", "revoke", "DB_URL", fpB},
	} {
		stdout, stderr, err := run("", args...)
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 6 {
			t.Errorf("%v: want exit 6, got %v\nstdout: %s\nstderr: %s", args, err, stdout, stderr)
		}
		if strings.Contains(stdout, "value") {
			t.Errorf("%v: printed a value: %q", args, stdout)
		}
		if !strings.Contains(stderr, "failed verification") || !strings.Contains(stderr, "dotsecenv validate") {
			t.Errorf("%v: unexpected stderr: %s", args, stderr)
		}
	}

	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("share or revoke wrote to the vault after refusing a tampered value")
	}
}
