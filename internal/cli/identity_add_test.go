package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
	"golang.org/x/term"
)

func newIdentityAddCLI(t *testing.T, vaultPaths []string) (*CLI, *MockVaultResolver, *MockGPGClient, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
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
			Login: newTestSignedLogin(t, "MYFINGERPRINT"), // current user's login
		},
		vaultResolver: mock,
		gpgClient:     gpgMock,
		output:        output.NewHandler(stdout, stderr),
	}

	return cli, mock, gpgMock, stdout, stderr
}

// createTempVaultFiles creates n temp files and returns their paths and a cleanup function.
func createTempVaultFiles(t *testing.T, n int) []string {
	t.Helper()
	paths := make([]string, n)
	for i := 0; i < n; i++ {
		f, err := os.CreateTemp("", "testvault_*.jsonl")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		paths[i] = f.Name()
		_ = f.Close()
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
	}
	return paths
}

func TestIdentityAdd_All(t *testing.T) {
	paths := createTempVaultFiles(t, 2)
	cli, mock, _, stdout, _ := newIdentityAddCLI(t, paths)

	err := cli.IdentityAdd("AABBCCDD", true, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mock.IdentityExistsInVault("AABBCCDD", 0) {
		t.Error("identity not added to vault 0")
	}
	if !mock.IdentityExistsInVault("AABBCCDD", 1) {
		t.Error("identity not added to vault 1")
	}

	out := stdout.String()
	if !strings.Contains(out, "added: identity AABBCCDD to vault 1") {
		t.Errorf("expected added message for vault 1, got: %s", out)
	}
	if !strings.Contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
	if !strings.Contains(out, "summary: added=2 skipped=0 failed=0") {
		t.Errorf("expected summary, got: %s", out)
	}
}

func TestIdentityAdd_SingleVaultByIndex(t *testing.T) {
	paths := createTempVaultFiles(t, 2)
	cli, mock, _, stdout, _ := newIdentityAddCLI(t, paths)

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
	if !strings.Contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
}

func TestIdentityAdd_SingleVaultByPath(t *testing.T) {
	paths := createTempVaultFiles(t, 2)
	cli, mock, _, stdout, _ := newIdentityAddCLI(t, paths)

	err := cli.IdentityAdd("AABBCCDD", false, paths[1], 0)
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
	if !strings.Contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
}

func TestIdentityAdd_AutoSelectSingleVault(t *testing.T) {
	paths := createTempVaultFiles(t, 1)
	cli, mock, _, _, _ := newIdentityAddCLI(t, paths)

	err := cli.IdentityAdd("AABBCCDD", false, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !mock.IdentityExistsInVault("AABBCCDD", 0) {
		t.Error("identity not added to the single vault")
	}
}

func TestIdentityAdd_MultipleVaultsNoTTY(t *testing.T) {
	// This test verifies behavior when no TTY is available.
	// Skip when /dev/tty is a real terminal (e.g., running from a terminal
	// session or git hook) since HandleInteractiveSelection opens /dev/tty
	// directly and would hang waiting for input.
	if tty, err := os.Open("/dev/tty"); err == nil {
		isTerm := term.IsTerminal(int(tty.Fd()))
		_ = tty.Close()
		if isTerm {
			t.Skip("skipping: /dev/tty is a real terminal; test requires no-TTY environment")
		}
	}

	paths := createTempVaultFiles(t, 2)
	cli, _, _, _, _ := newIdentityAddCLI(t, paths)

	// Without a TTY, resolveWritableVaultIndex should error asking for -v
	err := cli.IdentityAdd("AABBCCDD", false, "", 0)
	switch {
	case err == nil:
		t.Fatal("expected error when multiple vaults and no TTY")
	case !strings.Contains(err.Message, "specify target vault using -v") &&
		!strings.Contains(err.Message, "no terminal available"):
		t.Errorf("unexpected error message: %s", err.Message)
	}
}

func TestIdentityAdd_SkipsExisting(t *testing.T) {
	paths := createTempVaultFiles(t, 2)
	cli, mock, _, stdout, stderr := newIdentityAddCLI(t, paths)

	// Pre-add identity to vault 0
	mock.IdentitiesByVault[0] = map[string]vault.Identity{
		"AABBCCDD": {Fingerprint: "AABBCCDD"},
	}

	err := cli.IdentityAdd("AABBCCDD", true, "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "skipped: identity AABBCCDD already in vault 1") {
		t.Errorf("expected skipped message, got stderr: %s", stderrStr)
	}

	out := stdout.String()
	if !strings.Contains(out, "added: identity AABBCCDD to vault 2") {
		t.Errorf("expected added message for vault 2, got: %s", out)
	}
	if !strings.Contains(out, "summary: added=1 skipped=1 failed=0") {
		t.Errorf("expected summary, got: %s", out)
	}
}

func TestIdentityAdd_IndexOutOfRange(t *testing.T) {
	paths := createTempVaultFiles(t, 1)
	cli, _, _, _, _ := newIdentityAddCLI(t, paths)

	err := cli.IdentityAdd("AABBCCDD", false, "", 5) // only 1 vault
	switch {
	case err == nil:
		t.Fatal("expected error for out-of-range index")
	case !strings.Contains(err.Message, "exceeds number of configured vaults"):
		t.Errorf("unexpected error message: %s", err.Message)
	}
}

func TestIdentityAdd_UnknownVaultPath(t *testing.T) {
	paths := createTempVaultFiles(t, 1)
	cli, _, _, _, _ := newIdentityAddCLI(t, paths)

	err := cli.IdentityAdd("AABBCCDD", false, "/nonexistent.jsonl", 0)
	switch {
	case err == nil:
		t.Fatal("expected error for unknown vault path")
	case !strings.Contains(err.Message, "does not exist"):
		// resolveWritableVaultIndex checks os.Stat first
		t.Errorf("unexpected error message: %s", err.Message)
	}
}

func TestIdentityAdd_AlgorithmNotAllowed(t *testing.T) {
	paths := createTempVaultFiles(t, 1)
	cli, _, gpgMock, _, _ := newIdentityAddCLI(t, paths)

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
	switch {
	case err == nil:
		t.Fatal("expected algorithm not allowed error")
	case err.ExitCode != ExitAlgorithmNotAllowed:
		t.Errorf("expected ExitAlgorithmNotAllowed, got %d", err.ExitCode)
	}
}
