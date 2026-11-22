package main_test

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// gpgOutput runs gpg with env and stdin and returns its stdout.
func gpgOutput(t *testing.T, env []string, stdin string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", append([]string{"--batch", "--trust-model", "always"}, args...)...)
	cmd.Env = append(filteredEnv(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gpg %v: %v", args, err)
	}
	return out
}

// TestForgedSignerIdentity_Refused checks that a value signed by an attacker
// key, under a teammate's fingerprint, is refused by get and validate: both
// when only the teammate's public_key is swapped, and when the attacker also
// re-signs the identity entry so its hash and signature are self-consistent.
func TestForgedSignerIdentity_Refused(t *testing.T) {
	vaultPath, users := setupSharedVault(t, "UserA", "UserB", "UserC")
	a, fpA, fpB, fpC, env := users[0], users[0].fp, users[1].fp, users[2].fp, users[0].env
	if _, stderr, err := a.run("real-value", "secret", "store", "DB_URL"); err != nil {
		t.Fatalf("store: %v\n%s", err, stderr)
	}
	if _, stderr, err := a.run("", "secret", "share", "DB_URL", fpB); err != nil {
		t.Fatalf("share: %v\n%s", err, stderr)
	}
	original, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	attackerKey := base64.StdEncoding.EncodeToString(gpgOutput(t, env, "", "--export", fpC))
	sign := func(data string) string {
		return hex.EncodeToString(gpgOutput(t, env, data, "--local-user", fpC, "--detach-sign"))
	}

	for _, tc := range []struct {
		name       string
		selfSigned bool
		wantErr    string
	}{
		{"public key swapped", false, "hash mismatch"},
		{"self-consistent forged identity", true, "does not match identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entryLine := func(entry *vault.Entry, err error) string {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
				b, err := vault.MarshalEntry(*entry)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			lines := strings.Split(string(original), "\n")
			valueLine := -1
			var bits int
			for i, line := range lines {
				entry, err := vault.UnmarshalEntry([]byte(line))
				if err != nil {
					continue
				}
				if entry.Type == "value" && entry.SecretKey == "DB_URL" {
					valueLine = i
				}
				if entry.Type != "identity" {
					continue
				}
				data, err := vault.ParseIdentityData(entry)
				if err != nil || data.Fingerprint != fpB {
					continue
				}
				id := data.ToIdentity()
				bits = id.AlgorithmBits
				id.PublicKey = attackerKey
				if tc.selfSigned {
					id.SignedBy = fpB
					id.Hash = identity.ComputeIdentityHash(&id)
					id.Signature = sign(id.Hash)
				}
				lines[i] = entryLine(vault.CreateIdentityEntry(id))
			}
			if valueLine < 0 || bits == 0 {
				t.Fatal("fixture: identity or value line not found")
			}

			// A forged value signed by the attacker key in the teammate's name.
			ciphertext := gpgOutput(t, env, "attacker-value", "--armor", "--encrypt", "-r", fpA)
			entry, err := vault.UnmarshalEntry([]byte(lines[valueLine]))
			if err != nil {
				t.Fatal(err)
			}
			sv, err := vault.ParseSecretValue(entry)
			if err != nil {
				t.Fatal(err)
			}
			sv.SignedBy = fpB
			sv.Value = base64.StdEncoding.EncodeToString(ciphertext)
			sv.Hash = vault.ComputeSecretValueHash(sv, "DB_URL", bits)
			sv.Signature = sign(sv.Hash)
			lines[valueLine] = entryLine(vault.CreateValueEntry("DB_URL", *sv))
			if err := os.WriteFile(vaultPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
				t.Fatal(err)
			}

			stdout, stderr, err := a.run("", "secret", "get", "DB_URL")
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 6 {
				t.Errorf("get: want exit 6, got %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
			}
			if strings.Contains(stdout, "value") {
				t.Errorf("get printed a value: %q", stdout)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("get stderr does not mention %q: %s", tc.wantErr, stderr)
			}
			if _, _, err := a.run("", "validate"); err == nil {
				t.Error("validate passed a forged identity")
			}
		})
	}
}
