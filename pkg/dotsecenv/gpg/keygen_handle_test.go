package gpg

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAddKeyHandle(t *testing.T) {
	cases := []struct {
		name, template, want, wantErr string
	}{
		{"before commit", "Key-Type: eddsa\n%commit\n", "Key-Type: eddsa\nHandle: H\n%commit\n", ""},
		{"no commit", "Key-Type: eddsa\n", "Key-Type: eddsa\nHandle: H\n", ""},
		{"no commit, no newline", "Key-Type: eddsa", "Key-Type: eddsa\nHandle: H\n", ""},
		{"two keys", "Key-Type: a\n%commit\nKey-Type: b\n%commit\n", "", "exactly one key"},
		{"handle already set", "Key-Type: a\nhandle: x\n%commit\n", "", "must not set Handle"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := addKeyHandle(tc.template, "H")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestCreatedKeyFingerprint(t *testing.T) {
	const fpr = "35E5AA04C6C4A17477833C3A2F67AC5E7334F46B"
	cases := []struct {
		name, status, want string
		wantErr            bool
	}{
		{"match", "[GNUPG:] KEY_CONSIDERED " + fpr + " 0\n[GNUPG:] KEY_CREATED B " + fpr + " H\n", fpr, false},
		{"primary only", "[GNUPG:] KEY_CREATED P " + fpr + " H\n", fpr, false},
		{"lowercase", "[GNUPG:] KEY_CREATED B " + strings.ToLower(fpr) + " H\n", fpr, false},
		{"other handle only", "[GNUPG:] KEY_CREATED B " + fpr + " OTHER\n", "", true},
		{"no handle", "[GNUPG:] KEY_CREATED B " + fpr + "\n", "", true},
		{"subkey only", "[GNUPG:] KEY_CREATED S " + fpr + " H\n", "", true},
		{"missing", "gpg: key generated\n", "", true},
		{"two", "[GNUPG:] KEY_CREATED B " + fpr + " H\n[GNUPG:] KEY_CREATED B " + fpr + " H\n", "", true},
		{"bad fingerprint", "[GNUPG:] KEY_CREATED B NOTHEX H\n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := createdKeyFingerprint(tc.status, "H")
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("got %q, %v; want %q, error=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// With real GnuPG: a key created outside dotsecenv, with a newer creation
// time, is in the same keyring. GenerateKey must return its own key.
func TestGenerateKey_RealGPGReturnsOwnKey(t *testing.T) {
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed")
	}
	home, err := os.MkdirTemp("", "dse-gpg-") // short path: gpg-agent socket length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "gpg-agent").Run()
		_ = os.RemoveAll(home)
	})
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", home)

	previous := GetGPGProgram()
	t.Cleanup(func() { setGPGProgramInternal(previous) })
	setGPGProgramInternal(gpgPath)

	// The outside key has a creation time one day in the future, so a
	// "newest key" lookup would select it.
	future := time.Now().Add(24 * time.Hour).UTC().Format("20060102T150405")
	outside := exec.Command(gpgPath, "--batch", "--faked-system-time", future+"!",
		"--passphrase", "", "--quick-gen-key", "Outside <outside@example.test>", "ed25519", "sign", "never")
	if out, err := outside.CombinedOutput(); err != nil {
		t.Fatalf("create outside key: %v\n%s", err, out)
	}

	template, err := GenerateKeyTemplate(AlgoED25519, "Dotsecenv Test", "dse@example.test", &KeyTemplateOptions{NoPassphrase: true})
	if err != nil {
		t.Fatal(err)
	}
	fpr, err := (&GPGClient{NoPinentry: true}).GenerateKey(template)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	out, err := exec.Command(gpgPath, "--with-colons", "--list-secret-keys", fpr).Output()
	if err != nil {
		t.Fatalf("list %s: %v", fpr, err)
	}
	if !strings.Contains(string(out), "dse@example.test") || strings.Contains(string(out), "outside@example.test") {
		t.Fatalf("fingerprint %s is not the dotsecenv key:\n%s", fpr, out)
	}
	if _, err := os.Stat(filepath.Join(home, "pubring.kbx")); err != nil {
		t.Fatalf("expected keyring in temp GNUPGHOME: %v", err)
	}

	// Check the setup: the outside key must be the newest secret key, or
	// this test would not catch a "newest key" lookup.
	all, err := exec.Command(gpgPath, "--with-colons", "--list-secret-keys").Output()
	if err != nil {
		t.Fatal(err)
	}
	var newestFPR string
	var newest, current int64
	for _, line := range strings.Split(string(all), "\n") {
		f := strings.Split(line, ":")
		switch {
		case f[0] == "sec" && len(f) > 5:
			current, _ = strconv.ParseInt(f[5], 10, 64)
		case f[0] == "fpr" && len(f) > 9 && current > newest:
			newest, newestFPR, current = current, f[9], 0
		}
	}
	if newestFPR == "" || newestFPR == fpr {
		t.Fatalf("setup: the outside key is not the newest key (newest=%s, created=%s)", newestFPR, fpr)
	}
}
