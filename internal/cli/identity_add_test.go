package cli

import (
	"bytes"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

func newIdentityAddCLI(t *testing.T, vaultPaths []string) (*CLI, *MockVaultResolver, *MockGPGClient, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("DOTSECENV_FINGERPRINT", "")
	t.Setenv("DOTSECENV_CONFIG", "")

	mock := NewMockVaultResolver()
	mock.VaultPaths = vaultPaths
	for _, p := range vaultPaths {
		mock.VaultEntries = append(mock.VaultEntries, vault.VaultEntry{Path: p})
	}

	gpgMock := NewMockGPGClient()
	gpgMock.PublicKeyInfo["AABBCCDD"] = gpg.KeyInfo{
		Fingerprint:     "AABBCCDD",
		UID:             "Alice <alice@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   4096,
		CanEncrypt:      true,
		PublicKeyBase64: "base64pubkey",
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	cli := &CLI{
		config: config.Config{
			ApprovedAlgorithms: []config.ApprovedAlgorithm{
				{Algo: "RSA", MinBits: 2048},
			},
		},
		vaultResolver: mock,
		gpgClient:     gpgMock,
		output:        output.NewHandler(stdout, stderr),
	}

	return cli, mock, gpgMock, stdout, stderr
}

func TestIdentityAdd_All(t *testing.T) {
	cli, mock, _, stdout, _ := newIdentityAddCLI(t, []string{"/v1.jsonl", "/v2.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", true, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both vaults should have the identity
	if !mock.IdentityExistsInVault("AABBCCDD", 0) {
		t.Error("identity not added to vault 0")
	}
	if !mock.IdentityExistsInVault("AABBCCDD", 1) {
		t.Error("identity not added to vault 1")
	}

	out := stdout.String()
	if !contains(out, "added: identity AABBCCDD to vault 1") {
		t.Errorf("expected added message for vault 1, got: %s", out)
	}
	if !contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
	if !contains(out, "summary: added=2 skipped=0 failed=0") {
		t.Errorf("expected summary, got: %s", out)
	}
}

func TestIdentityAdd_SingleVaultByIndex(t *testing.T) {
	cli, mock, _, stdout, _ := newIdentityAddCLI(t, []string{"/v1.jsonl", "/v2.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", false, "", 2) // 1-based index
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.IdentityExistsInVault("AABBCCDD", 0) {
		t.Error("identity should not be in vault 0")
	}
	if !mock.IdentityExistsInVault("AABBCCDD", 1) {
		t.Error("identity not added to vault 1")
	}

	out := stdout.String()
	if !contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
}

func TestIdentityAdd_SingleVaultByPath(t *testing.T) {
	cli, mock, _, stdout, _ := newIdentityAddCLI(t, []string{"/v1.jsonl", "/v2.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", false, "/v2.jsonl", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if mock.IdentityExistsInVault("AABBCCDD", 0) {
		t.Error("identity should not be in vault 0")
	}
	if !mock.IdentityExistsInVault("AABBCCDD", 1) {
		t.Error("identity not added to vault 1")
	}

	out := stdout.String()
	if !contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
}

func TestIdentityAdd_AutoSelectSingleVault(t *testing.T) {
	cli, mock, _, _, _ := newIdentityAddCLI(t, []string{"/only.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", false, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mock.IdentityExistsInVault("AABBCCDD", 0) {
		t.Error("identity not added to the single vault")
	}
}

func TestIdentityAdd_ErrorMultipleVaultsNoFlag(t *testing.T) {
	cli, _, _, _, _ := newIdentityAddCLI(t, []string{"/v1.jsonl", "/v2.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", false, "", 0)
	if err == nil {
		t.Fatal("expected error when multiple vaults and no --all or -v")
	}
	if !contains(err.Message, "multiple vaults configured") {
		t.Errorf("unexpected error message: %s", err.Message)
	}
}

func TestIdentityAdd_SkipsExisting(t *testing.T) {
	cli, mock, _, stdout, stderr := newIdentityAddCLI(t, []string{"/v1.jsonl", "/v2.jsonl"})

	// Pre-add identity to vault 0
	mock.IdentitiesByVault[0] = map[string]vault.Identity{
		"AABBCCDD": {Fingerprint: "AABBCCDD"},
	}

	err := cli.IdentityAdd("AABBCCDD", true, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stderrStr := stderr.String()
	if !contains(stderrStr, "skipped: identity AABBCCDD already in vault 1") {
		t.Errorf("expected skipped message, got stderr: %s", stderrStr)
	}

	out := stdout.String()
	if !contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
	if !contains(out, "summary: added=1 skipped=1 failed=0") {
		t.Errorf("expected summary, got: %s", out)
	}
}

func TestIdentityAdd_IndexOutOfRange(t *testing.T) {
	cli, _, _, _, _ := newIdentityAddCLI(t, []string{"/v1.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", false, "", 5) // only 1 vault
	if err == nil {
		t.Fatal("expected error for out-of-range index")
	}
	if !contains(err.Message, "exceeds number of configured vaults") {
		t.Errorf("unexpected error message: %s", err.Message)
	}
}

func TestIdentityAdd_UnknownVaultPath(t *testing.T) {
	cli, _, _, _, _ := newIdentityAddCLI(t, []string{"/v1.jsonl"})

	err := cli.IdentityAdd("AABBCCDD", false, "/nonexistent.jsonl", 0)
	if err == nil {
		t.Fatal("expected error for unknown vault path")
	}
	if !contains(err.Message, "vault path not found") {
		t.Errorf("unexpected error message: %s", err.Message)
	}
}

func TestIdentityAdd_AlgorithmNotAllowed(t *testing.T) {
	cli, _, gpgMock, _, _ := newIdentityAddCLI(t, []string{"/v1.jsonl"})

	// Override config to only allow ED25519
	cli.config.ApprovedAlgorithms = []config.ApprovedAlgorithm{
		{Algo: "ED25519", MinBits: 0},
	}
	gpgMock.PublicKeyInfo["AABBCCDD"] = gpg.KeyInfo{
		Fingerprint:     "AABBCCDD",
		UID:             "Alice <alice@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   4096,
		CanEncrypt:      true,
		PublicKeyBase64: "base64pubkey",
	}

	err := cli.IdentityAdd("AABBCCDD", false, "", 0)
	if err == nil {
		t.Fatal("expected algorithm not allowed error")
	}
	if err.ExitCode != ExitAlgorithmNotAllowed {
		t.Errorf("expected ExitAlgorithmNotAllowed, got %d", err.ExitCode)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
