package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

func TestIsRSAAlgorithm(t *testing.T) {
	for algo, want := range map[string]bool{
		"RSA":           true,
		"RSA-4096":      true,
		"rsa":           true,
		"RSA-S":         true,
		"ECC P-384":     false,
		"EdDSA Ed25519": false,
		"":              false,
	} {
		if got := isRSAAlgorithm(algo); got != want {
			t.Errorf("isRSAAlgorithm(%q) = %v, want %v", algo, got, want)
		}
	}
}

func TestIdentityCreate_RSARejectedByDefaultExplainsWhy(t *testing.T) {
	cfg := config.DefaultConfig()
	var stdout, stderr bytes.Buffer
	err := identityCreateCore(IdentityCreateOptions{Algorithm: "RSA4096", Name: "T", Email: "t@example.test", TemplateOnly: true},
		&cfg, &identityCreateIO{stdout: &stdout, stderr: &stderr, stdin: strings.NewReader("")}, true)
	if err == nil || err.ExitCode != ExitAlgorithmNotAllowed {
		t.Fatalf("got %v, want ExitAlgorithmNotAllowed", err)
	}
	for _, want := range []string{"PKCS #1 v1.5", "algo: RSA", rsaLegacyDocsURL} {
		if !strings.Contains(err.Message, want) {
			t.Errorf("error message missing %q:\n%s", want, err.Message)
		}
	}
}

func TestIdentityCreate_RSAOptInWarns(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ApprovedAlgorithms = append(cfg.ApprovedAlgorithms, config.ApprovedAlgorithm{Algo: "RSA", MinBits: 3072})
	var stdout, stderr bytes.Buffer
	err := identityCreateCore(IdentityCreateOptions{Algorithm: "RSA4096", Name: "T", Email: "t@example.test", TemplateOnly: true},
		&cfg, &identityCreateIO{stdout: &stdout, stderr: &stderr, stdin: strings.NewReader("")}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stderr.String(), "WARNING: RSA keys are legacy") {
		t.Errorf("expected legacy warning on stderr, got:\n%s", stderr.String())
	}
}

func TestIdentityCreate_NonRSANoWarning(t *testing.T) {
	cfg := config.DefaultConfig()
	var stdout, stderr bytes.Buffer
	err := identityCreateCore(IdentityCreateOptions{Algorithm: "ED25519", Name: "T", Email: "t@example.test", TemplateOnly: true},
		&cfg, &identityCreateIO{stdout: &stdout, stderr: &stderr, stdin: strings.NewReader("")}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(stderr.String(), "legacy") {
		t.Errorf("unexpected legacy warning for ED25519:\n%s", stderr.String())
	}
}

func TestLegacyIdentityCheck(t *testing.T) {
	ids := []vault.Identity{
		{UID: "Alice <a@example.test>", Fingerprint: "AAAA", Algorithm: "RSA"},
		{UID: "Bob <b@example.test>", Fingerprint: "BBBB", Algorithm: "EdDSA", Curve: "Ed25519"},
	}
	check, ok := legacyIdentityCheck(0, "vault.yaml", ids)
	if !ok {
		t.Fatal("expected a warning for a vault with an RSA identity")
	}
	if check.Name != "vault_1_legacy_keys" || check.Status != "warning" {
		t.Errorf("got name=%q status=%q", check.Name, check.Status)
	}
	if !strings.Contains(check.Message, "1 RSA identity") {
		t.Errorf("message = %q", check.Message)
	}
	if !strings.Contains(check.Details, "Alice <a@example.test> (AAAA)") || strings.Contains(check.Details, "Bob") {
		t.Errorf("details = %q", check.Details)
	}

	if _, ok := legacyIdentityCheck(0, "vault.yaml", ids[1:]); ok {
		t.Error("expected no warning for a vault without RSA identities")
	}
}
