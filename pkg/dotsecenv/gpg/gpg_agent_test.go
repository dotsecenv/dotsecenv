package gpg

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testFPR = "0123456789ABCDEF0123456789ABCDEF01234567"

func useAgentGPG(t *testing.T, script string) {
	t.Helper()
	t.Setenv("TEST_FPR", testFPR)
	if runtime.GOOS == "windows" {
		t.Skip("fixture requires a POSIX shell")
	}
	previous := GetGPGProgram()
	t.Cleanup(func() { setGPGProgramInternal(previous) })
	program := filepath.Join(t.TempDir(), "gpg")
	if err := os.WriteFile(program, []byte("#!/bin/sh\n"+script), 0700); err != nil {
		t.Fatal(err)
	}
	setGPGProgramInternal(program)
}

func TestAgentOperationsNoPinentry(t *testing.T) {
	useAgentGPG(t, `
for required in --pinentry-mode=error --status-fd=2 --batch --no-tty; do
    case " $* " in
        *" $required "*) ;;
        *) echo "missing $required" >&2; exit 2 ;;
    esac
done
handle=$(sed -n 's/^Handle: //p')
if [ -n "$handle" ]; then printf '[GNUPG:] KEY_CREATED B %s %s\n' "$TEST_FPR" "$handle" >&2; fi
if [ "$TEST_GPG_LOCKED" = yes ]; then
    printf '[GNUPG:] ERROR get_passphrase 67108949\n' >&2
    echo 'gpg: interaction unavailable' >&2
    exit 2
fi
printf 'result'
`)
	t.Setenv("GPG_TTY", "/dev/inherited-tty")
	for _, locked := range []string{"no", "yes"} {
		t.Run(locked, func(t *testing.T) {
			t.Setenv("TEST_GPG_LOCKED", locked)
			client := &GPGClient{NoPinentry: true}
			operations := map[string]func() (string, error){
				"generate": func() (string, error) { return client.GenerateKey("Key-Type: eddsa\n%commit\n") },
				"sign":     func() (string, error) { return client.SignDataWithAgent("TESTFP", []byte("data")) },
				"decrypt": func() (string, error) {
					value, err := client.DecryptWithAgent([]byte("ciphertext"), "TESTFP")
					return string(value), err
				},
			}
			for name, operation := range operations {
				t.Run(name, func(t *testing.T) {
					value, err := operation()
					if locked == "yes" {
						if !errors.Is(err, ErrPinentryRequired) {
							t.Fatalf("got %v, want pinentry-required error", err)
						}
						if !strings.Contains(err.Error(), "GPG_ERR_NO_PIN_ENTRY: GPG requires pinentry, but --no-pinentry disables it.") {
							t.Errorf("native GPG error missing: %v", err)
						}
						if value != "" || !strings.Contains(err.Error(), "interaction unavailable") {
							t.Fatalf("value = %q, error = %v", value, err)
						}
						return
					}
					want := "result"
					if name == "generate" {
						want = testFPR
					}
					if name == "sign" {
						want = "726573756c74"
					}
					if err != nil || value != want {
						t.Fatalf("value = %q, error = %v; want %q", value, err, want)
					}
				})
			}
		})
	}
}

func TestAgentPinentryErrorClassification(t *testing.T) {
	useAgentGPG(t, `cat >/dev/null
printf '%s\n' "$TEST_GPG_STATUS" >&2
printf 'gpg: diagnostic retained\n' >&2
exit 2
`)
	cases := []struct {
		name       string
		status     string
		noPinentry bool
		want       bool
	}{
		{"numeric", "[GNUPG:] FAILURE sign 85", true, true},
		{"source", "[GNUPG:] ERROR pkdecrypt_failed 67108949", true, true},
		{"symbol suffix", "[GNUPG:] FAILURE sign 67108949_NO_PIN_ENTRY", true, true},
		{"symbol", "[GNUPG:] ERROR get_passphrase NO_PIN_ENTRY", true, true},
		{"missing program", "[GNUPG:] FAILURE sign 85", false, false},
		{"missing key", "[GNUPG:] NO_SECKEY ABCDEF\n[GNUPG:] FAILURE decrypt 17", true, false},
		{"canceled", "[GNUPG:] FAILURE sign 99", true, false},
		{"text only", "gpg: No pinentry", true, false},
		{"unknown status", "[GNUPG:] FUTURE_STATUS 85", true, false},
		{"malformed", "[GNUPG:] FAILURE sign", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_GPG_STATUS", tc.status)
			client := &GPGClient{NoPinentry: tc.noPinentry}
			value, err := client.DecryptWithAgent([]byte("ciphertext"), "")
			if err == nil || len(value) != 0 || errors.Is(err, ErrPinentryRequired) != tc.want {
				t.Fatalf("value = %q, error = %v, want pinentry required = %v", value, err, tc.want)
			}
			if !strings.Contains(err.Error(), "diagnostic retained") {
				t.Errorf("GPG diagnostic missing: %v", err)
			}
			if !strings.Contains(err.Error(), tc.status) {
				t.Errorf("GPG status missing: %v", err)
			}
		})
	}
}

func TestAgentOperationsRespectGPGConfiguration(t *testing.T) {
	useAgentGPG(t, `
for arg in "$@"; do
    case "$arg" in
        --pinentry-mode*) echo "unexpected pinentry override" >&2; exit 2 ;;
    esac
done
handle=$(sed -n 's/^Handle: //p')
if [ -n "$handle" ]; then printf '[GNUPG:] KEY_CREATED B %s %s\n' "$TEST_FPR" "$handle" >&2; fi
printf 'result'
`)
	for _, tty := range []string{"", "/dev/inherited-tty"} {
		t.Run("GPG_TTY="+tty, func(t *testing.T) {
			t.Setenv("GPG_TTY", tty)
			client := &GPGClient{}
			if _, err := client.SignDataWithAgent("TESTFP", []byte("data")); err != nil {
				t.Errorf("signing must follow GPG configuration: %v", err)
			}
			if _, err := client.DecryptWithAgent([]byte("ciphertext"), "TESTFP"); err != nil {
				t.Errorf("decryption must follow GPG configuration: %v", err)
			}
			if fpr, err := client.GenerateKey("Key-Type: eddsa\n%commit\n"); err != nil || fpr != testFPR {
				t.Errorf("key generation must follow GPG configuration: fpr=%q err=%v", fpr, err)
			}
		})
	}
}
