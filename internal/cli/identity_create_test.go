package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/policy"
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

// withInjectedPolicy replaces loadPolicy for the duration of t.
func withInjectedPolicy(t *testing.T, pol policy.Policy, err error) {
	t.Helper()
	orig := loadPolicy
	loadPolicy = func() (policy.Policy, []string, error) { return pol, nil, err }
	t.Cleanup(func() { loadPolicy = orig })
}

func standaloneTemplateOpts(algo string) IdentityCreateOptions {
	return IdentityCreateOptions{Algorithm: algo, Name: "Test", Email: "test@example.test", TemplateOnly: true}
}

// The system policy must apply when no user config exists.
func TestIdentityCreateStandalone_PolicyRestrictsAlgorithm(t *testing.T) {
	withInjectedPolicy(t, policy.Policy{
		Dir: "/etc/dotsecenv/policy.d",
		Fragments: []policy.Fragment{{
			Path:               "/etc/dotsecenv/policy.d/00-base.yaml",
			ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "EdDSA", Curves: []string{"Ed25519"}, MinBits: 255}},
		}},
	}, nil)

	var stdout, stderr bytes.Buffer
	out := output.NewHandler(&stdout, &stderr)

	err := IdentityCreateStandalone(standaloneTemplateOpts("P384"), out)
	if err == nil || err.ExitCode != ExitAlgorithmNotAllowed {
		t.Fatalf("P384: got %v, want exit code %d (algorithm not allowed by policy)", err, ExitAlgorithmNotAllowed)
	}

	stdout.Reset()
	if err := IdentityCreateStandalone(standaloneTemplateOpts("ED25519"), out); err != nil {
		t.Fatalf("ED25519: got %v, want success", err)
	}
	if !strings.Contains(stdout.String(), "gpg --batch --generate-key") {
		t.Errorf("ED25519: expected template output, got: %s", stdout.String())
	}
}

// A policy load error must stop the command (fail closed), with the same
// exit code as the other commands.
func TestIdentityCreateStandalone_PolicyLoadErrorFailsClosed(t *testing.T) {
	withInjectedPolicy(t, policy.Policy{}, fmt.Errorf("%w: test", policy.ErrInsecurePermissions))

	var stdout, stderr bytes.Buffer
	err := IdentityCreateStandalone(standaloneTemplateOpts("ED25519"), output.NewHandler(&stdout, &stderr))
	if err == nil || err.ExitCode != ExitAccessDenied {
		t.Fatalf("got %v, want exit code %d", err, ExitAccessDenied)
	}
}

// The policy gpg.program must replace the PATH lookup.
func TestIdentityCreateStandalone_PolicyGPGProgram(t *testing.T) {
	previous := gpg.GetGPGProgram()
	t.Cleanup(func() {
		if previous == "" {
			previous = "PATH"
		}
		_ = gpg.ValidateAndSetGPGProgram(previous)
	})

	missing := filepath.Join(t.TempDir(), "no-such-gpg")
	withInjectedPolicy(t, policy.Policy{
		Dir:       "/etc/dotsecenv/policy.d",
		Fragments: []policy.Fragment{{Path: "/etc/dotsecenv/policy.d/00-base.yaml", GPG: config.GPGConfig{Program: missing}}},
	}, nil)

	var stdout, stderr bytes.Buffer
	err := IdentityCreateStandalone(standaloneTemplateOpts("ED25519"), output.NewHandler(&stdout, &stderr))
	if err == nil || err.ExitCode != ExitGPGError || !strings.Contains(err.Message, missing) {
		t.Fatalf("got %v, want exit code %d naming %s", err, ExitGPGError, missing)
	}
}
