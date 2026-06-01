package cli

import (
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// newSecretStoreCLI builds a *CLI wired with mocks for exercising SecretPut.
//
// entryPaths populate config.Entries (so resolveWritableVaultIndex can resolve a
// -v index), while availablePaths drive GetAvailableVaultPathsWithIndices (the
// MockVaultResolver reports VaultPaths as the set of available vaults). Passing
// an entry without a matching available path models a configured-but-missing
// vault: the index resolves, but the vault did not load.
//
// The injected GPG mock and signed login make checkFingerprintRequired succeed
// so the vault-existence guard inside SecretPut is reached. Stderr is captured
// so tests can assert the absence of the identity auto-add warnings.
func newSecretStoreCLI(t *testing.T, entryPaths, availablePaths []string) (*CLI, *strings.Builder) {
	t.Helper()

	mock := NewMockVaultResolver()
	mock.VaultPaths = availablePaths
	for _, p := range entryPaths {
		mock.VaultEntries = append(mock.VaultEntries, vault.VaultEntry{Path: p})
	}

	gpgMock := NewMockGPGClient()
	gpgMock.PublicKeyInfo["MYFINGERPRINT"] = gpg.KeyInfo{
		Fingerprint:     "MYFINGERPRINT",
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   4096,
		CanEncrypt:      true,
		PublicKeyBase64: "base64pubkey",
	}

	stdout := &strings.Builder{}
	stderr := &strings.Builder{}

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

	return cli, stderr
}

// TestSecretStore_MissingVaultFile_FriendlyError verifies that 'secret store'
// against a configured-but-missing vault fails immediately with a friendly
// message that names the requested version, returns ExitVaultError, and never
// prints the misleading identity auto-add warnings.
func TestSecretStore_MissingVaultFile_FriendlyError(t *testing.T) {
	// Vault index 1 is configured but did not load (no matching available path).
	cli, stderr := newSecretStoreCLI(t, []string{"/vault1.yaml"}, nil)

	err := cli.SecretPut("PULUMI_CONFIG_PASSPHRASE", "", 1, "v")

	if err == nil {
		t.Fatal("SecretPut against a missing vault: got nil error, want a friendly failure")
	}

	// Friendly message names the missing vault and the init command with the
	// requested version (-v 1).
	if !strings.Contains(err.Message, "does not exist") {
		t.Errorf("error message %q does not mention that the vault does not exist", err.Message)
	}
	if !strings.Contains(err.Message, "init vault -v 1") {
		t.Errorf("error message %q does not instruct to run 'init vault -v 1' (requested version)", err.Message)
	}

	if err.ExitCode != ExitVaultError {
		t.Errorf("exit code = %d, want ExitVaultError (%d)", err.ExitCode, ExitVaultError)
	}

	// The guard must fire BEFORE ensureIdentityInVault, so the misleading
	// auto-add warnings must never be printed.
	stderrText := stderr.String()
	if strings.Contains(stderrText, "did not previously exist") {
		t.Errorf("stderr contains misleading 'did not previously exist' warning:\n%s", stderrText)
	}
	if strings.Contains(stderrText, "adding identity to vault") {
		t.Errorf("stderr contains misleading 'adding identity to vault' warning:\n%s", stderrText)
	}
}

// TestSecretStore_ExistingVault_NoMissingError is a regression guard: when the
// target vault loaded successfully, SecretPut must NOT short-circuit with the
// "does not exist" error, so legitimate first-time self-add still proceeds into
// ensureIdentityInVault.
func TestSecretStore_ExistingVault_NoMissingError(t *testing.T) {
	// Vault index 1 is both configured and available (loaded).
	cli, _ := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})

	err := cli.SecretPut("PULUMI_CONFIG_PASSPHRASE", "", 1, "secret-value")

	if err != nil && strings.Contains(err.Message, "does not exist") {
		t.Errorf("vault is available but SecretPut returned a 'does not exist' error: %q", err.Message)
	}
}
