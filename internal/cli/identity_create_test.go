package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
)

func TestIdentityCreate_NoPinentry(t *testing.T) {
	program := filepath.Join(t.TempDir(), "gpg")
	if err := os.WriteFile(program, []byte(`#!/bin/sh
case " $* " in
    *" --pinentry-mode=error "*) ;;
    *) echo 'pinentry was not disabled' >&2; exit 2 ;;
esac
cat >/dev/null
printf '[GNUPG:] FAILURE genkey 85\n' >&2
exit 2
`), 0700); err != nil {
		t.Fatal(err)
	}
	previous := gpg.GetGPGProgram()
	t.Cleanup(func() {
		if previous == "" {
			previous = "PATH"
		}
		_ = gpg.ValidateAndSetGPGProgram(previous)
	})
	if err := gpg.ValidateAndSetGPGProgram(program); err != nil {
		t.Fatal(err)
	}
	cli, _, _ := newSecretStoreCLI(t, nil, nil)
	var stdout, stderr bytes.Buffer
	cli.output = output.NewHandler(&stdout, &stderr)
	err := cli.IdentityCreate(IdentityCreateOptions{Algorithm: "RSA4096", Name: "Test", Email: "test@example.test", NoPinentry: true})
	if err == nil || err.ExitCode != ExitGPGError || !strings.Contains(err.Message, "GPG_ERR_NO_PIN_ENTRY") {
		t.Fatalf("got %v, want pinentry required with exit code 4", err)
	}
	if strings.Contains(stdout.String(), "GPG will prompt") {
		t.Errorf("advertised a disabled prompt: %s", stdout.String())
	}
}

func TestPrintSuccessOutput_WithConfig(t *testing.T) {
	var buf bytes.Buffer

	printSuccessOutput(&buf, "Test User", "test@example.com", "ED25519", "ABCD1234FINGERPRINT", true)

	output := buf.String()

	// Should show single "Next step" with login command
	if !strings.Contains(output, "Next step - login to dotsecenv:") {
		t.Error("expected 'Next step - login to dotsecenv:' when config exists")
	}
	if !strings.Contains(output, "dotsecenv login ABCD1234FINGERPRINT") {
		t.Error("expected login command with fingerprint")
	}

	// Should NOT suggest init config
	if strings.Contains(output, "dotsecenv init config") {
		t.Error("should not suggest 'dotsecenv init config' when config already exists")
	}
}

func TestPrintSuccessOutput_WithoutConfig(t *testing.T) {
	var buf bytes.Buffer

	printSuccessOutput(&buf, "Test User", "test@example.com", "ED25519", "ABCD1234FINGERPRINT", false)

	output := buf.String()

	// Should show numbered steps
	if !strings.Contains(output, "Next steps:") {
		t.Error("expected 'Next steps:' when no config exists")
	}
	if !strings.Contains(output, "dotsecenv init config") {
		t.Error("expected 'dotsecenv init config' suggestion when no config exists")
	}
	if !strings.Contains(output, "Review the created config, then login:") {
		t.Error("expected review guidance when no config exists")
	}
	if !strings.Contains(output, "dotsecenv login ABCD1234FINGERPRINT") {
		t.Error("expected login command with fingerprint")
	}

	// Should NOT show single "Next step" format
	if strings.Contains(output, "Next step - login to dotsecenv:") {
		t.Error("should not show single next step format when no config exists")
	}
}
