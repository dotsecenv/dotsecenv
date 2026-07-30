package cli

import (
	"encoding/base64"
	"io"
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
func newSecretStoreCLI(t *testing.T, entryPaths, availablePaths []string) (*CLI, *MockVaultResolver, *strings.Builder) {
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
		// No terminal by default so shared-store confirmation never opens
		// /dev/tty under 'go test'; prompt-path tests stub promptConfirm.
		hasTTY: func() bool { return false },
	}

	return cli, mock, stderr
}

// TestSecretStore_MissingVaultFile_FriendlyError verifies that 'secret store'
// against a configured-but-missing vault fails immediately with a friendly
// message that names the requested version, returns ExitVaultError, and never
// prints the misleading identity auto-add warnings.
func TestSecretStore_MissingVaultFile_FriendlyError(t *testing.T) {
	// Vault index 1 is configured but did not load (no matching available path).
	cli, _, stderr := newSecretStoreCLI(t, []string{"/vault1.yaml"}, nil)

	err := cli.SecretPut("PULUMI_CONFIG_PASSPHRASE", "", 1, "v", StoreSharePrompt)

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
	cli, _, _ := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})

	err := cli.SecretPut("PULUMI_CONFIG_PASSPHRASE", "", 1, "secret-value", StoreSharePrompt)

	if err != nil && strings.Contains(err.Message, "does not exist") {
		t.Errorf("vault is available but SecretPut returned a 'does not exist' error: %q", err.Message)
	}
}

// storeTestIdentity returns a minimal valid identity for SecretPut tests.
func storeTestIdentity(fingerprint, publicKey string) vault.Identity {
	return vault.Identity{
		Fingerprint:   fingerprint,
		UID:           fingerprint + " <" + strings.ToLower(fingerprint) + "@example.com>",
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		PublicKey:     publicKey,
	}
}

// seedSharedSecret places a secret in vault 0 whose latest value is available
// to the given fingerprints (pre-sorted by the caller).
func seedSharedSecret(mock *MockVaultResolver, key string, availableTo []string) {
	mock.Secrets[0] = map[string]vault.Secret{
		key: {
			Key: key,
			Values: []vault.SecretValue{
				{
					AvailableTo: availableTo,
					SignedBy:    availableTo[len(availableTo)-1],
					Value:       "b2xkLXZhbHVl", // base64("old-value")
				},
			},
		},
	}
}

// TestSecretStore_ExistingSharedSecret_CarriesRecipientsForward verifies that
// re-storing a shared secret preserves the latest value's recipient set: the
// new entry must stay available to (and be encrypted to) every prior
// recipient, not just the storer. Narrowing access is 'secret revoke'.
// Without a terminal, the default mode warns about the kept recipients and
// proceeds, so piped and CI stores keep working.
func TestSecretStore_ExistingSharedSecret_CarriesRecipientsForward(t *testing.T) {
	cli, mock, stderr := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)
	_ = mock.AddIdentity(storeTestIdentity("CIFINGERPRINT", "ci-pubkey"), 0)
	seedSharedSecret(mock, "DATABASE_URL", []string{"CIFINGERPRINT", "MYFINGERPRINT"})

	err := cli.SecretPut("DATABASE_URL", "", 1, "rotated-value", StoreSharePrompt)
	if err != nil {
		t.Fatalf("SecretPut over a shared secret failed: %s", err.Message)
	}

	stderrText := stderr.String()
	if !strings.Contains(stderrText, "is shared") || !strings.Contains(stderrText, "CIFINGERPRINT") {
		t.Errorf("stderr does not warn about the kept recipient set:\n%s", stderrText)
	}

	stored, ok := mock.Secrets[0]["DATABASE_URL"]
	if !ok || len(stored.Values) == 0 {
		t.Fatal("no secret value was stored")
	}
	newValue := stored.Values[len(stored.Values)-1]

	wantRecipients := []string{"CIFINGERPRINT", "MYFINGERPRINT"}
	if len(newValue.AvailableTo) != len(wantRecipients) {
		t.Fatalf("available_to = %v, want %v", newValue.AvailableTo, wantRecipients)
	}
	for i, fp := range wantRecipients {
		if newValue.AvailableTo[i] != fp {
			t.Errorf("available_to[%d] = %q, want %q (full set: %v)", i, newValue.AvailableTo[i], fp, newValue.AvailableTo)
		}
	}

	// The mock encodes the recipient public keys into the ciphertext, so the
	// stored value proves the encryption call included every recipient.
	ciphertext, decodeErr := base64.StdEncoding.DecodeString(newValue.Value)
	if decodeErr != nil {
		t.Fatalf("stored value is not valid base64: %v", decodeErr)
	}
	for _, pubKey := range []string{"ci-pubkey", "my-pubkey"} {
		if !strings.Contains(string(ciphertext), pubKey) {
			t.Errorf("ciphertext %q was not encrypted to %q", ciphertext, pubKey)
		}
	}
}

// TestSecretStore_NewSecret_EncryptedToStorerOnly verifies that a first-time
// store still targets only the storer's key.
func TestSecretStore_NewSecret_EncryptedToStorerOnly(t *testing.T) {
	cli, mock, _ := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)

	err := cli.SecretPut("API_KEY", "", 1, "fresh-value", StoreSharePrompt)
	if err != nil {
		t.Fatalf("SecretPut for a new secret failed: %s", err.Message)
	}

	stored := mock.Secrets[0]["API_KEY"]
	if len(stored.Values) == 0 {
		t.Fatal("no secret value was stored")
	}
	newValue := stored.Values[len(stored.Values)-1]
	if len(newValue.AvailableTo) != 1 || newValue.AvailableTo[0] != "MYFINGERPRINT" {
		t.Errorf("available_to = %v, want [MYFINGERPRINT]", newValue.AvailableTo)
	}
}

// TestSecretStore_ShareFlag_SkipsWarning verifies that --share keeps the
// recipient set with no warning and no confirmation attempt.
func TestSecretStore_ShareFlag_SkipsWarning(t *testing.T) {
	cli, mock, stderr := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})
	cli.hasTTY = func() bool { return true }
	cli.promptConfirm = func(prompt string, _ io.Writer) (bool, *Error) {
		t.Fatalf("promptConfirm called with %q despite --share", prompt)
		return false, nil
	}

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)
	_ = mock.AddIdentity(storeTestIdentity("CIFINGERPRINT", "ci-pubkey"), 0)
	seedSharedSecret(mock, "DATABASE_URL", []string{"CIFINGERPRINT", "MYFINGERPRINT"})

	err := cli.SecretPut("DATABASE_URL", "", 1, "rotated-value", StoreShareAlways)
	if err != nil {
		t.Fatalf("SecretPut --share failed: %s", err.Message)
	}

	if strings.Contains(stderr.String(), "is shared") {
		t.Errorf("--share must not print the shared-secret warning:\n%s", stderr.String())
	}

	newValue := mock.Secrets[0]["DATABASE_URL"].Values[0]
	if len(newValue.AvailableTo) != 2 {
		t.Errorf("available_to = %v, want both recipients", newValue.AvailableTo)
	}
}

// TestSecretStore_NoShareFlag_EncryptsToStorerOnly verifies that --no-share
// narrows the new value to the storer's identity with no warning.
func TestSecretStore_NoShareFlag_EncryptsToStorerOnly(t *testing.T) {
	cli, mock, stderr := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)
	_ = mock.AddIdentity(storeTestIdentity("CIFINGERPRINT", "ci-pubkey"), 0)
	seedSharedSecret(mock, "DATABASE_URL", []string{"CIFINGERPRINT", "MYFINGERPRINT"})

	err := cli.SecretPut("DATABASE_URL", "", 1, "rotated-value", StoreShareNever)
	if err != nil {
		t.Fatalf("SecretPut --no-share failed: %s", err.Message)
	}

	if strings.Contains(stderr.String(), "is shared") {
		t.Errorf("--no-share must not print the shared-secret warning:\n%s", stderr.String())
	}

	newValue := mock.Secrets[0]["DATABASE_URL"].Values[0]
	if len(newValue.AvailableTo) != 1 || newValue.AvailableTo[0] != "MYFINGERPRINT" {
		t.Fatalf("available_to = %v, want [MYFINGERPRINT]", newValue.AvailableTo)
	}

	ciphertext, decodeErr := base64.StdEncoding.DecodeString(newValue.Value)
	if decodeErr != nil {
		t.Fatalf("stored value is not valid base64: %v", decodeErr)
	}
	if strings.Contains(string(ciphertext), "ci-pubkey") {
		t.Errorf("--no-share ciphertext %q was encrypted to the CI key", ciphertext)
	}
}

// TestSecretStore_PromptConfirmed_KeepsSharing verifies the interactive path:
// with a terminal, the default mode asks for confirmation and a "yes" keeps
// the recipient set.
func TestSecretStore_PromptConfirmed_KeepsSharing(t *testing.T) {
	cli, mock, stderr := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})
	cli.hasTTY = func() bool { return true }
	prompted := false
	cli.promptConfirm = func(string, io.Writer) (bool, *Error) {
		prompted = true
		return true, nil
	}

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)
	_ = mock.AddIdentity(storeTestIdentity("CIFINGERPRINT", "ci-pubkey"), 0)
	seedSharedSecret(mock, "DATABASE_URL", []string{"CIFINGERPRINT", "MYFINGERPRINT"})

	err := cli.SecretPut("DATABASE_URL", "", 1, "rotated-value", StoreSharePrompt)
	if err != nil {
		t.Fatalf("SecretPut after confirmation failed: %s", err.Message)
	}
	if !prompted {
		t.Error("confirmation prompt was never shown despite a terminal being available")
	}
	if !strings.Contains(stderr.String(), "is shared") {
		t.Errorf("stderr does not warn about the kept recipient set:\n%s", stderr.String())
	}

	newValue := mock.Secrets[0]["DATABASE_URL"].Values[0]
	if len(newValue.AvailableTo) != 2 {
		t.Errorf("available_to = %v, want both recipients", newValue.AvailableTo)
	}
}

// TestSecretStore_PromptDeclined_AbortsWithoutWriting verifies that declining
// the confirmation cancels the store entirely: no value entry is written and
// the error points at the --share/--no-share flags.
func TestSecretStore_PromptDeclined_AbortsWithoutWriting(t *testing.T) {
	cli, mock, _ := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})
	cli.hasTTY = func() bool { return true }
	cli.promptConfirm = func(string, io.Writer) (bool, *Error) {
		return false, nil
	}

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)
	_ = mock.AddIdentity(storeTestIdentity("CIFINGERPRINT", "ci-pubkey"), 0)
	seedSharedSecret(mock, "DATABASE_URL", []string{"CIFINGERPRINT", "MYFINGERPRINT"})

	err := cli.SecretPut("DATABASE_URL", "", 1, "rotated-value", StoreSharePrompt)
	if err == nil {
		t.Fatal("SecretPut succeeded despite the user declining the confirmation")
	}
	if !strings.Contains(err.Message, "--share") || !strings.Contains(err.Message, "--no-share") {
		t.Errorf("cancellation message %q does not point at the --share/--no-share flags", err.Message)
	}

	stored := mock.Secrets[0]["DATABASE_URL"]
	if len(stored.Values) != 1 || stored.Values[0].Value != "b2xkLXZhbHVl" {
		t.Errorf("vault was modified after a declined confirmation: %+v", stored.Values)
	}
}

// TestSecretStore_MissingRecipientIdentity_Fails verifies that when a prior
// recipient's identity cannot be resolved, store fails loudly instead of
// silently dropping them from the new entry.
func TestSecretStore_MissingRecipientIdentity_Fails(t *testing.T) {
	cli, mock, _ := newSecretStoreCLI(t, []string{"/vault1.yaml"}, []string{"/vault1.yaml"})

	_ = mock.AddIdentity(storeTestIdentity("MYFINGERPRINT", "my-pubkey"), 0)
	// GHOSTFINGERPRINT is on the recipient list but has no identity entry.
	seedSharedSecret(mock, "DATABASE_URL", []string{"GHOSTFINGERPRINT", "MYFINGERPRINT"})

	err := cli.SecretPut("DATABASE_URL", "", 1, "rotated-value", StoreSharePrompt)
	if err == nil {
		t.Fatal("SecretPut succeeded despite an unresolvable recipient; it must fail rather than drop them")
	}
	if !strings.Contains(err.Message, "recipient identity not found") {
		t.Errorf("error message %q does not name the missing recipient problem", err.Message)
	}
	if err.ExitCode != ExitVaultError {
		t.Errorf("exit code = %d, want ExitVaultError (%d)", err.ExitCode, ExitVaultError)
	}
}
