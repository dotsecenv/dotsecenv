package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// MockVaultResolver and MockGPGClient live in testhelpers_test.go.

// TestSecretPut_WithVaultPath tests the -v flag functionality
func TestSecretPut_WithVaultPath(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "") // Clear env to avoid config pollution

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()
	mockGPGClient.PublicKeyInfo[testFP] = gpg.KeyInfo{
		Fingerprint:     testFP,
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   2048,
		CanEncrypt:      true,
		PublicKeyBase64: "mock_public_key_base64",
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader("mysecretvalue\n"),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Add identity to vault 0
	mockVaultResolver.IdentitiesByVault[0] = map[string]vault.Identity{
		testFP: mockVaultResolver.Identities[testFP],
	}

	receivedIndex := -1
	mockVaultResolver.AddSecretFunc = func(secret vault.Secret, index int) error {
		receivedIndex = index
		return nil
	}

	// Use -v flag
	putErr := cli.SecretPut("MY_SECRET", vaultPath, 0, "")
	if putErr != nil {
		t.Fatalf("SecretPut with -v failed unexpectedly: %v", putErr)
	}

	if receivedIndex != 0 {
		t.Errorf("Expected AddSecret to be called with index 0, got %d", receivedIndex)
	}

	if len(mockVaultResolver.SavedVaults) != 1 || mockVaultResolver.SavedVaults[0] != 0 {
		t.Errorf("Expected SaveVault to be called with index 0, got %v", mockVaultResolver.SavedVaults)
	}
}

// TestSecretPut_WithFromIndex tests the --from flag functionality
func TestSecretPut_WithFromIndex(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "") // Clear env to avoid config pollution

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()
	mockGPGClient.PublicKeyInfo[testFP] = gpg.KeyInfo{
		Fingerprint:     testFP,
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   2048,
		CanEncrypt:      true,
		PublicKeyBase64: "mock_public_key_base64",
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader("mysecretvalue\n"),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	mockVaultResolver.VaultPaths = []string{"/vault1.yaml", "/vault2.yaml", "/vault3.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
		{Path: "/vault2.yaml"},
		{Path: "/vault3.yaml"},
	}

	// Identity in vault 2 (index 1)
	mockVaultResolver.IdentitiesByVault[1] = map[string]vault.Identity{
		testFP: mockVaultResolver.Identities[testFP],
	}

	receivedIndex := -1
	mockVaultResolver.AddSecretFunc = func(secret vault.Secret, index int) error {
		receivedIndex = index
		return nil
	}

	// Test --from 2 (index 1)
	err := cli.SecretPut("MY_SECRET", "", 2, "")
	if err != nil {
		t.Fatalf("SecretPut with --from 2 failed unexpectedly: %v", err)
	}

	if receivedIndex != 1 {
		t.Errorf("Expected AddSecret to be called with index 1, got %d", receivedIndex)
	}

	if len(mockVaultResolver.SavedVaults) != 1 || mockVaultResolver.SavedVaults[0] != 1 {
		t.Errorf("Expected SaveVault to be called with index 1, got %v", mockVaultResolver.SavedVaults)
	}
}

// TestSecretPut_FromIndexOutOfRange tests error handling for invalid --from index
func TestSecretPut_FromIndexOutOfRange(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()
	mockGPGClient.PublicKeyInfo[testFP] = gpg.KeyInfo{
		Fingerprint:     testFP,
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   2048,
		CanEncrypt:      true,
		PublicKeyBase64: "mock_public_key_base64",
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader("mysecretvalue\n"),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
		{Path: "/vault2.yaml"},
	}

	// Test -v 4 (out of range)
	err := cli.SecretPut("MY_SECRET", "", 4, "")
	switch {
	case err == nil:
		t.Fatalf("Expected SecretPut with -v 4 to fail, but it succeeded")
	case !strings.Contains(err.Message, "-v index 4 exceeds number of configured vaults"):
		t.Errorf("Expected error message to contain '-v index 4 exceeds number of configured vaults', got: %s", err.Message)
	}
}

// MockGPGClientWithDecrypt extends MockGPGClient with custom decrypt function
type MockGPGClientWithDecrypt struct {
	*MockGPGClient
	DecryptFunc func(ciphertext []byte, fingerprint string) ([]byte, error)
}

func (m *MockGPGClientWithDecrypt) DecryptWithAgent(ciphertext []byte, fingerprint string) ([]byte, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ciphertext, fingerprint)
	}
	return nil, fmt.Errorf("not implemented")
}

// TestSecretGet_WithFromIndex tests the -v N flag functionality for secret get
func TestSecretGet_WithFromIndex(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "") // Clear env to avoid config pollution

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	now := time.Now().UTC()
	olderTime := now.Add(-1 * time.Hour)

	// Vault 0 has old value, Vault 1 has new value
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key: "MY_SECRET",
			Values: []vault.SecretValue{
				{AddedAt: olderTime, Value: "dmF1bHQxX3ZhbHVl", AvailableTo: []string{testFP}},
			},
		},
	}
	mockVaultResolver.Secrets[1] = map[string]vault.Secret{
		"MY_SECRET": {
			Key: "MY_SECRET",
			Values: []vault.SecretValue{
				{AddedAt: now, Value: "dmF1bHQyX3ZhbHVl", AvailableTo: []string{testFP}},
			},
		},
	}

	mockVaultResolver.VaultPaths = []string{"/vault1.yaml", "/vault2.yaml", "/vault3.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
		{Path: "/vault2.yaml"},
		{Path: "/vault3.yaml"},
	}

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			text := string(ciphertext)
			if strings.Contains(text, "vault1") {
				return []byte("vault1_value"), nil
			}
			if strings.Contains(text, "vault2") {
				return []byte("vault2_value"), nil
			}
			return ciphertext, nil
		},
	}
	mockGPGClient.PublicKeyInfo[testFP] = gpg.KeyInfo{
		Fingerprint:     testFP,
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   2048,
		CanEncrypt:      true,
		PublicKeyBase64: "mock_public_key_base64",
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// Test -v 2 with --all (should get from vault2, index 1)
	// Using all=true to bypass the vault manager requirement
	err := cli.SecretGet("MY_SECRET", true, false, false, "", 2)
	if err != nil {
		t.Fatalf("SecretGet with -v 2 failed unexpectedly: %v", err)
	}

	out := stdoutBuf.String()
	if !strings.Contains(out, "vault2_value") {
		t.Errorf("Expected output to contain 'vault2_value', got: %s", out)
	}
}

// TestSecretForget_Basic tests basic secret forget functionality
func TestSecretForget_Basic(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()
	mockGPGClient.PublicKeyInfo[testFP] = gpg.KeyInfo{
		Fingerprint:     testFP,
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   2048,
		CanEncrypt:      true,
		PublicKeyBase64: "mock_public_key_base64",
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Add identity to vault 0
	mockVaultResolver.IdentitiesByVault[0] = map[string]vault.Identity{
		testFP: mockVaultResolver.Identities[testFP],
	}

	// Add an existing secret
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key:     "MY_SECRET",
			AddedAt: time.Now(),
			Values: []vault.SecretValue{
				{Value: "secret_value", AvailableTo: []string{testFP}},
			},
		},
	}

	var addedSecret vault.Secret
	mockVaultResolver.AddSecretFunc = func(secret vault.Secret, index int) error {
		addedSecret = secret
		return nil
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// Forget the secret
	forgetErr := cli.SecretForget("MY_SECRET", vaultPath, 0, false)
	if forgetErr != nil {
		t.Fatalf("SecretForget failed unexpectedly: %v", forgetErr)
	}

	// Verify the deletion marker was created
	if len(addedSecret.Values) != 1 {
		t.Fatalf("Expected 1 value (deletion marker), got %d", len(addedSecret.Values))
	}

	deletionValue := addedSecret.Values[0]
	if !deletionValue.Deleted {
		t.Error("Deletion marker should have Deleted=true")
	}
	if len(deletionValue.AvailableTo) != 0 {
		t.Error("Deletion marker should have empty AvailableTo")
	}
	if deletionValue.Value != "" {
		t.Error("Deletion marker should have empty Value")
	}

	// Verify output
	if !strings.Contains(stdoutBuf.String(), "marked as deleted") {
		t.Errorf("Expected success message, got: %s", stdoutBuf.String())
	}
}

// TestSecretForget_AlreadyDeleted tests that forgetting an already-deleted secret fails
func TestSecretForget_AlreadyDeleted(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Add an already-deleted secret
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key:     "MY_SECRET",
			AddedAt: time.Now(),
			Values: []vault.SecretValue{
				{Value: "secret_value", AvailableTo: []string{testFP}},
				{Value: "", AvailableTo: []string{}, Deleted: true},
			},
		},
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	// Try to forget the already-deleted secret
	forgetErr := cli.SecretForget("MY_SECRET", vaultPath, 0, false)
	switch {
	case forgetErr == nil:
		t.Fatal("SecretForget should fail for already-deleted secret")
	case !strings.Contains(forgetErr.Message, "already deleted"):
		t.Errorf("Expected 'already deleted' error, got: %s", forgetErr.Message)
	}
}

// TestSecretForget_NotFound tests that forgetting a non-existent secret fails
func TestSecretForget_NotFound(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	// Try to forget a non-existent secret
	forgetErr := cli.SecretForget("NONEXISTENT", vaultPath, 0, false)
	switch {
	case forgetErr == nil:
		t.Fatal("SecretForget should fail for non-existent secret")
	case !strings.Contains(forgetErr.Message, "not found"):
		t.Errorf("Expected 'not found' error, got: %s", forgetErr.Message)
	}
}

// TestSecretPut_BlockedByDeleted tests that putting to a deleted secret fails
func TestSecretPut_BlockedByDeleted(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()
	mockGPGClient.PublicKeyInfo[testFP] = gpg.KeyInfo{
		Fingerprint:     testFP,
		UID:             "Test User <test@example.com>",
		Algorithm:       "RSA",
		AlgorithmBits:   2048,
		CanEncrypt:      true,
		PublicKeyBase64: "mock_public_key_base64",
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Add identity to vault 0
	mockVaultResolver.IdentitiesByVault[0] = map[string]vault.Identity{
		testFP: mockVaultResolver.Identities[testFP],
	}

	// Add a deleted secret
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"DELETED_SECRET": {
			Key:     "DELETED_SECRET",
			AddedAt: time.Now(),
			Values: []vault.SecretValue{
				{Value: "old_value", AvailableTo: []string{testFP}},
				{Value: "", AvailableTo: []string{}, Deleted: true},
			},
		},
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader("new_secret_value\n"),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	// Try to put to a deleted secret
	putErr := cli.SecretPut("DELETED_SECRET", vaultPath, 0, "")
	switch {
	case putErr == nil:
		t.Fatal("SecretPut should fail for deleted secret")
	case !strings.Contains(putErr.Message, "has been deleted"):
		t.Errorf("Expected 'has been deleted' error, got: %s", putErr.Message)
	}

	if !strings.Contains(putErr.Message, "cannot overwrite") {
		t.Errorf("Expected 'cannot overwrite' in error, got: %s", putErr.Message)
	}
}

// TestSecretForget_NoAccess tests that forgetting without access fails
func TestSecretForget_NoAccess(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"
	otherFP := "OTHERFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Add a secret that the test user doesn't have access to
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"OTHER_SECRET": {
			Key:     "OTHER_SECRET",
			AddedAt: time.Now(),
			Values: []vault.SecretValue{
				{Value: "secret_value", AvailableTo: []string{otherFP}}, // Not testFP
			},
		},
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	// Try to forget a secret we don't have access to
	forgetErr := cli.SecretForget("OTHER_SECRET", vaultPath, 0, false)
	switch {
	case forgetErr == nil:
		t.Fatal("SecretForget should fail without access")
	case !strings.Contains(forgetErr.Message, "access denied"):
		t.Errorf("Expected 'access denied' error, got: %s", forgetErr.Message)
	}
}

// TestSecretList_AllVaults tests listing all secrets from all vaults
func TestSecretList_AllVaults(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()

	// Set up vaults with secrets
	mockVaultResolver.VaultPaths = []string{"/vault1.yaml", "/vault2.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
		{Path: "/vault2.yaml"},
	}

	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"SECRET_A": {Key: "SECRET_A", Values: []vault.SecretValue{{Value: "a"}}},
		"SECRET_B": {Key: "SECRET_B", Values: []vault.SecretValue{{Value: "b"}}},
	}
	mockVaultResolver.Secrets[1] = map[string]vault.Secret{
		"SECRET_C": {Key: "SECRET_C", Values: []vault.SecretValue{{Value: "c"}}},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		vaultResolver: mockVaultResolver,
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// List all secrets
	err := cli.SecretList(false, "", 0)
	if err != nil {
		t.Fatalf("SecretList failed: %v", err)
	}

	out := stdoutBuf.String()
	// Should contain all 3 secrets sorted
	if !strings.Contains(out, "SECRET_A") {
		t.Errorf("Expected output to contain 'SECRET_A', got: %s", out)
	}
	if !strings.Contains(out, "SECRET_B") {
		t.Errorf("Expected output to contain 'SECRET_B', got: %s", out)
	}
	if !strings.Contains(out, "SECRET_C") {
		t.Errorf("Expected output to contain 'SECRET_C', got: %s", out)
	}
}

// TestSecretList_SpecificVault tests listing secrets from a specific vault
func TestSecretList_SpecificVault(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()

	// Set up vaults with secrets
	mockVaultResolver.VaultPaths = []string{"/vault1.yaml", "/vault2.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
		{Path: "/vault2.yaml"},
	}

	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"SECRET_A": {Key: "SECRET_A", Values: []vault.SecretValue{{Value: "a"}}},
		"SECRET_B": {Key: "SECRET_B", Values: []vault.SecretValue{{Value: "b"}}},
	}
	mockVaultResolver.Secrets[1] = map[string]vault.Secret{
		"SECRET_C": {Key: "SECRET_C", Values: []vault.SecretValue{{Value: "c"}}},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		vaultResolver: mockVaultResolver,
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// List secrets from vault 2 only (index 2 = second vault)
	err := cli.SecretList(false, "", 2)
	if err != nil {
		t.Fatalf("SecretList failed: %v", err)
	}

	out := stdoutBuf.String()
	// Should contain only SECRET_C
	if strings.Contains(out, "SECRET_A") {
		t.Errorf("Expected output NOT to contain 'SECRET_A', got: %s", out)
	}
	if strings.Contains(out, "SECRET_B") {
		t.Errorf("Expected output NOT to contain 'SECRET_B', got: %s", out)
	}
	if !strings.Contains(out, "SECRET_C") {
		t.Errorf("Expected output to contain 'SECRET_C', got: %s", out)
	}
}

// TestSecretList_JSONOutput tests JSON output for secret list
func TestSecretList_JSONOutput(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()

	// Set up vaults with secrets
	mockVaultResolver.VaultPaths = []string{"/vault1.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
	}

	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"SECRET_A": {Key: "SECRET_A", Values: []vault.SecretValue{{Value: "a"}}},
		"SECRET_B": {Key: "SECRET_B", Values: []vault.SecretValue{{Value: "b", Deleted: true}}},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		vaultResolver: mockVaultResolver,
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// List secrets as JSON
	err := cli.SecretList(true, "", 0)
	if err != nil {
		t.Fatalf("SecretList failed: %v", err)
	}

	out := stdoutBuf.String()
	// Should be valid JSON
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("Expected JSON array output, got: %s", out)
	}
	if !strings.Contains(out, `"key"`) {
		t.Errorf("Expected JSON to contain 'key' field, got: %s", out)
	}
	if !strings.Contains(out, `"vault"`) {
		t.Errorf("Expected JSON to contain 'vault' field, got: %s", out)
	}
}

// TestSecretList_WithDeletedSecrets tests that deleted secrets are shown with (deleted) marker
func TestSecretList_WithDeletedSecrets(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()

	// Set up vault with a deleted secret
	mockVaultResolver.VaultPaths = []string{"/vault1.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
	}

	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"ACTIVE_SECRET": {Key: "ACTIVE_SECRET", Values: []vault.SecretValue{{Value: "a"}}},
		"DELETED_SECRET": {Key: "DELETED_SECRET", Values: []vault.SecretValue{
			{Value: "old", AvailableTo: []string{"fp1"}},
			{Value: "", AvailableTo: []string{}, Deleted: true},
		}},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		vaultResolver: mockVaultResolver,
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// List all secrets
	err := cli.SecretList(false, "", 0)
	if err != nil {
		t.Fatalf("SecretList failed: %v", err)
	}

	out := stdoutBuf.String()
	// Active secret should be shown
	if !strings.Contains(out, "ACTIVE_SECRET") {
		t.Errorf("Expected output to contain 'ACTIVE_SECRET', got: %s", out)
	}
	// Deleted secret should have (deleted) marker
	if !strings.Contains(out, "DELETED_SECRET (deleted)") {
		t.Errorf("Expected output to contain 'DELETED_SECRET (deleted)', got: %s", out)
	}
}

// TestSecretList_Empty tests listing when no secrets exist
func TestSecretList_Empty(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()

	// Set up empty vault
	mockVaultResolver.VaultPaths = []string{"/vault1.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		vaultResolver: mockVaultResolver,
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// List all secrets
	err := cli.SecretList(false, "", 0)
	if err != nil {
		t.Fatalf("SecretList failed: %v", err)
	}

	out := stdoutBuf.String()
	if !strings.Contains(out, "No secrets found") {
		t.Errorf("Expected 'No secrets found', got: %s", out)
	}
}

// TestSecretList_VaultPath tests listing secrets from a specific vault path
func TestSecretList_VaultPath(t *testing.T) {
	mockVaultResolver := NewMockVaultResolver()

	// Set up vaults with secrets
	mockVaultResolver.VaultPaths = []string{"/vault1.yaml", "/vault2.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{
		{Path: "/vault1.yaml"},
		{Path: "/vault2.yaml"},
	}

	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"SECRET_A": {Key: "SECRET_A", Values: []vault.SecretValue{{Value: "a"}}},
	}
	mockVaultResolver.Secrets[1] = map[string]vault.Secret{
		"SECRET_B": {Key: "SECRET_B", Values: []vault.SecretValue{{Value: "b"}}},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		vaultResolver: mockVaultResolver,
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	// List secrets from vault1.yaml only
	err := cli.SecretList(false, "/vault1.yaml", 0)
	if err != nil {
		t.Fatalf("SecretList failed: %v", err)
	}

	out := stdoutBuf.String()
	// Should contain only SECRET_A
	if !strings.Contains(out, "SECRET_A") {
		t.Errorf("Expected output to contain 'SECRET_A', got: %s", out)
	}
	if strings.Contains(out, "SECRET_B") {
		t.Errorf("Expected output NOT to contain 'SECRET_B', got: %s", out)
	}
}

// TestSecretGet_WarnsWithoutTTY tests that secret get emits a warning when not in a TTY
func TestSecretGet_WarnsWithoutTTY(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	testFP := "TESTFINGERPRINT"

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	// Setup mock vault resolver with a secret
	mockVaultResolver := NewMockVaultResolver()
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key: "MY_SECRET",
			Values: []vault.SecretValue{
				{Value: "c2VjcmV0", AvailableTo: []string{testFP}},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			return []byte("decrypted_value"), nil
		},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""), // Not a TTY
		output:        output.NewHandler(stdoutBuf, stderrBuf),
		hasTTY:        func() bool { return false }, // Simulate no controlling terminal
	}

	// Use --all to bypass vault manager requirement in test
	err := cli.SecretGet("MY_SECRET", true, false, false, "", 0)

	if err != nil {
		t.Fatalf("Expected SecretGet to succeed, got: %v", err)
	}

	// Verify warning was emitted
	stderr := stderrBuf.String()
	if !strings.Contains(stderr, "non-interactive terminal") {
		t.Errorf("Expected non-interactive warning, got stderr: %s", stderr)
	}
	if !strings.Contains(stderr, "dotsecenv.com") {
		t.Errorf("Expected dotsecenv.com URL in warning, got stderr: %s", stderr)
	}
}

func TestSmartJSONValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType string // "raw" or "string"
	}{
		{"json_object", `{"key":"val"}`, "raw"},
		{"json_array", `[1,2,3]`, "raw"},
		{"nested_json", `{"a":{"b":1}}`, "raw"},
		{"plain_string", "hello world", "string"},
		{"invalid_json_brace", "{not json", "string"},
		{"empty_string", "", "string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := smartJSONValue(tt.input)
			switch tt.wantType {
			case "raw":
				raw, ok := got.(json.RawMessage)
				if !ok {
					t.Fatalf("expected json.RawMessage, got %T", got)
				}
				if string(raw) != tt.input {
					t.Errorf("expected %s, got %s", tt.input, string(raw))
				}
			case "string":
				s, ok := got.(string)
				if !ok {
					t.Fatalf("expected string, got %T", got)
				}
				if s != tt.input {
					t.Errorf("expected %q, got %q", tt.input, s)
				}
			}
		})
	}
}

func TestSecretForget_IgnoreNotFound_NotFound(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	forgetErr := cli.SecretForget("NONEXISTENT", vaultPath, 0, true)
	if forgetErr != nil {
		t.Fatalf("SecretForget with ignoreNotFound=true should succeed for non-existent secret, got: %v", forgetErr)
	}
}

func TestSecretForget_IgnoreNotFound_NoValues(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Secret exists but has no values
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key:     "MY_SECRET",
			AddedAt: time.Now(),
			Values:  []vault.SecretValue{},
		},
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	forgetErr := cli.SecretForget("MY_SECRET", vaultPath, 0, true)
	if forgetErr != nil {
		t.Fatalf("SecretForget with ignoreNotFound=true should succeed for secret with no values, got: %v", forgetErr)
	}
}

func TestSecretForget_IgnoreNotFound_AlreadyDeleted(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	testFP := "TESTFINGERPRINT"

	mockVaultResolver.Identities[testFP] = vault.Identity{
		Fingerprint:   testFP,
		PublicKey:     "mock_public_key",
		Algorithm:     "RSA",
		AlgorithmBits: 2048,
	}

	mockGPGClient := NewMockGPGClient()

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	tmpFile, err := os.CreateTemp("", "testvault_*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	_ = tmpFile.Close()

	vaultPath := tmpFile.Name()
	mockVaultResolver.VaultPaths = []string{vaultPath}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: vaultPath}}

	// Secret exists but is already deleted
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key:     "MY_SECRET",
			AddedAt: time.Now(),
			Values: []vault.SecretValue{
				{Value: "secret_value", AvailableTo: []string{testFP}},
				{Value: "", AvailableTo: []string{}, Deleted: true},
			},
		},
	}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(&bytes.Buffer{}, &bytes.Buffer{}),
	}

	forgetErr := cli.SecretForget("MY_SECRET", vaultPath, 0, true)
	if forgetErr != nil {
		t.Fatalf("SecretForget with ignoreNotFound=true should succeed for already-deleted secret, got: %v", forgetErr)
	}
}

func TestSecretGet_JSONOutput(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	testFP := "TESTFINGERPRINT"

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	mockVaultResolver := NewMockVaultResolver()
	secretTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"API_KEY": {
			Key: "API_KEY",
			Values: []vault.SecretValue{
				{AddedAt: secretTime, Value: "c2VjcmV0", AvailableTo: []string{testFP}},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			return []byte("my_api_key_value"), nil
		},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	getErr := cli.SecretGet("API_KEY", false, false, true, "", 0)
	if getErr != nil {
		t.Fatalf("SecretGet with jsonOutput=true failed: %v", getErr)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdoutBuf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdoutBuf.String())
	}

	if result["value"] != "my_api_key_value" {
		t.Errorf("Expected value 'my_api_key_value', got: %v", result["value"])
	}
	if result["vault"] != "/vault.yaml" {
		t.Errorf("Expected vault '/vault.yaml', got: %v", result["vault"])
	}
	if _, ok := result["added_at"]; !ok {
		t.Error("Expected 'added_at' field in JSON output")
	}
}

func TestSecretGet_JSONOutput_SmartMarshal(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	testFP := "TESTFINGERPRINT"

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
		Login: newTestSignedLogin(t, testFP),
	}

	mockVaultResolver := NewMockVaultResolver()
	secretTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"DB_CONFIG": {
			Key: "DB_CONFIG",
			Values: []vault.SecretValue{
				{AddedAt: secretTime, Value: "c2VjcmV0", AvailableTo: []string{testFP}},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	// Return a JSON object as the decrypted value
	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			return []byte(`{"db":"host","port":5432}`), nil
		},
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	getErr := cli.SecretGet("DB_CONFIG", false, false, true, "", 0)
	if getErr != nil {
		t.Fatalf("SecretGet with jsonOutput=true failed: %v", getErr)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdoutBuf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdoutBuf.String())
	}

	// The value should be an embedded object, not a double-escaped string
	valueObj, ok := result["value"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected value to be a JSON object (smart marshaled), got %T: %v", result["value"], result["value"])
	}
	if valueObj["db"] != "host" {
		t.Errorf("Expected db='host', got: %v", valueObj["db"])
	}
	if valueObj["port"] != float64(5432) {
		t.Errorf("Expected port=5432, got: %v", valueObj["port"])
	}
}

// TestSecretGet_FallbackToGPGAgent tests that secret get succeeds when the logged-in
// fingerprint is NOT in AvailableTo but the GPG agent can still decrypt (different key in agent).
func TestSecretGet_FallbackToGPGAgent(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	loggedInFP := "LOGGED_IN_FP"
	otherFP := "OTHER_FP_IN_AGENT"

	mockVaultResolver := NewMockVaultResolver()
	// Secret is encrypted for otherFP, NOT the logged-in identity
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"HCLOUD_TOKEN": {
			Key: "HCLOUD_TOKEN",
			Values: []vault.SecretValue{
				{AddedAt: time.Now().UTC(), Value: "c2VjcmV0", AvailableTo: []string{otherFP}},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			// GPG agent can decrypt with whatever key it has
			return []byte("my_hcloud_token"), nil
		},
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "RSA", MinBits: 2048}},
		Login:              newTestSignedLogin(t, loggedInFP),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	err := cli.SecretGet("HCLOUD_TOKEN", false, false, false, "", 0)
	if err != nil {
		t.Fatalf("SecretGet should succeed via GPG agent fallback, got: %v", err)
	}

	out := stdoutBuf.String()
	if !strings.Contains(out, "my_hcloud_token") {
		t.Errorf("Expected decrypted value 'my_hcloud_token', got: %s", out)
	}
}

// TestSecretGet_FallbackToGPGAgent_AllMode tests --all mode decrypts values
// even when the logged-in fingerprint is not in AvailableTo.
func TestSecretGet_FallbackToGPGAgent_AllMode(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	loggedInFP := "LOGGED_IN_FP"
	otherFP := "OTHER_FP_IN_AGENT"

	now := time.Now().UTC()
	older := now.Add(-1 * time.Hour)

	mockVaultResolver := NewMockVaultResolver()
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"MY_SECRET": {
			Key: "MY_SECRET",
			Values: []vault.SecretValue{
				{AddedAt: older, Value: "b2xk", AvailableTo: []string{loggedInFP}},
				{AddedAt: now, Value: "bmV3", AvailableTo: []string{otherFP}},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	decryptCalls := 0
	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			decryptCalls++
			return []byte(fmt.Sprintf("decrypted_%d", decryptCalls)), nil
		},
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "RSA", MinBits: 2048}},
		Login:              newTestSignedLogin(t, loggedInFP),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	err := cli.SecretGet("MY_SECRET", true, false, false, "", 0)
	if err != nil {
		t.Fatalf("SecretGet --all should succeed, got: %v", err)
	}

	// Both values should be decrypted (not just the one matching loggedInFP)
	if decryptCalls != 2 {
		t.Errorf("Expected 2 decrypt calls (both values), got %d", decryptCalls)
	}
}

// TestSecretGet_FallbackNotFound tests that when a secret truly doesn't exist,
// the error is "not found" rather than "access denied".
func TestSecretGet_FallbackNotFound(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	mockVaultResolver := NewMockVaultResolver()
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}
	// No secrets stored

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			t.Fatal("DecryptWithAgent should not be called for a non-existent secret")
			return nil, nil
		},
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "RSA", MinBits: 2048}},
		Login:              newTestSignedLogin(t, "SOMEFP"),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	err := cli.SecretGet("NONEXISTENT", false, false, false, "", 0)
	switch {
	case err == nil:
		t.Fatal("Expected error for non-existent secret")
	case err.ExitCode != ExitVaultError:
		t.Errorf("Expected ExitVaultError, got exit code: %d", err.ExitCode)
	case !strings.Contains(err.Message, "not found"):
		t.Errorf("Expected 'not found' in error message, got: %s", err.Message)
	}
}

// TestSecretGet_JSONOutput_AllMode_IncludesAvailableToAndSignedBy verifies that
// `secret get NAME --all --json` exposes per-value available_to and signed_by,
// which are required for auditing access control across versions.
func TestSecretGet_JSONOutput_AllMode_IncludesAvailableToAndSignedBy(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	loggedInFP := "ALICEFP"
	otherFP := "BOBFP"

	now := time.Now().UTC()
	older := now.Add(-1 * time.Hour)

	mockVaultResolver := NewMockVaultResolver()
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"DB_PASSWORD": {
			Key: "DB_PASSWORD",
			Values: []vault.SecretValue{
				{AddedAt: older, Value: "b2xk", AvailableTo: []string{loggedInFP}, SignedBy: loggedInFP},
				{AddedAt: now, Value: "bmV3", AvailableTo: []string{loggedInFP, otherFP}, SignedBy: otherFP},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			return []byte("plaintext"), nil
		},
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "RSA", MinBits: 2048}},
		Login:              newTestSignedLogin(t, loggedInFP),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	if err := cli.SecretGet("DB_PASSWORD", true, false, true, "", 0); err != nil {
		t.Fatalf("SecretGet --all --json failed: %v", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(stdoutBuf.Bytes(), &results); err != nil {
		t.Fatalf("Failed to parse JSON output: %v\nOutput: %s", err, stdoutBuf.String())
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 entries, got %d", len(results))
	}

	// Sorted newest-first: results[0] is the recent value (signed by Bob, shared with both)
	got := results[0]
	if got["signed_by"] != otherFP {
		t.Errorf("Expected signed_by=%q on newest value, got: %v", otherFP, got["signed_by"])
	}
	availableTo, ok := got["available_to"].([]interface{})
	if !ok {
		t.Fatalf("Expected available_to to be an array on newest value, got %T: %v", got["available_to"], got["available_to"])
	}
	if len(availableTo) != 2 {
		t.Errorf("Expected 2 fingerprints on newest value, got %d", len(availableTo))
	}

	// results[1] is the older value (signed by Alice, only Alice has access)
	older2 := results[1]
	if older2["signed_by"] != loggedInFP {
		t.Errorf("Expected signed_by=%q on older value, got: %v", loggedInFP, older2["signed_by"])
	}
}

// TestSecretGet_JSONOutput_NoAll_OmitsAvailableToAndSignedBy verifies that the
// single-value JSON output stays lean and does not leak access metadata.
func TestSecretGet_JSONOutput_NoAll_OmitsAvailableToAndSignedBy(t *testing.T) {
	t.Setenv("DOTSECENV_CONFIG", "")

	testFP := "TESTFP"

	mockVaultResolver := NewMockVaultResolver()
	mockVaultResolver.Secrets[0] = map[string]vault.Secret{
		"API_KEY": {
			Key: "API_KEY",
			Values: []vault.SecretValue{
				{AddedAt: time.Now().UTC(), Value: "c2VjcmV0", AvailableTo: []string{testFP}, SignedBy: testFP},
			},
		},
	}
	mockVaultResolver.VaultPaths = []string{"/vault.yaml"}
	mockVaultResolver.VaultEntries = []vault.VaultEntry{{Path: "/vault.yaml"}}

	mockGPGClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			return []byte("plaintext"), nil
		},
	}

	mockConfig := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "RSA", MinBits: 2048}},
		Login:              newTestSignedLogin(t, testFP),
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}

	cli := &CLI{
		config:        mockConfig,
		vaultResolver: mockVaultResolver,
		gpgClient:     mockGPGClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdoutBuf, stderrBuf),
	}

	if err := cli.SecretGet("API_KEY", false, false, true, "", 0); err != nil {
		t.Fatalf("SecretGet --json failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(stdoutBuf.Bytes(), &result); err != nil {
		t.Fatalf("Failed to parse JSON: %v\nOutput: %s", err, stdoutBuf.String())
	}

	if _, present := result["available_to"]; present {
		t.Errorf("Expected available_to to be omitted in non-all JSON output, got: %v", result["available_to"])
	}
	if _, present := result["signed_by"]; present {
		t.Errorf("Expected signed_by to be omitted in non-all JSON output, got: %v", result["signed_by"])
	}
}

// TestVaultDescribeSecretJSON_OmitemptyContract documents the JSON contract for
// VaultDescribeSecretJSON: AvailableTo is omitted for deleted secrets and
// secrets with no values, and present for active secrets with recipients.
func TestVaultDescribeSecretJSON_OmitemptyContract(t *testing.T) {
	cases := []struct {
		name         string
		input        VaultDescribeSecretJSON
		wantContains []string
		wantOmits    []string
	}{
		{
			name:         "active secret with recipients",
			input:        VaultDescribeSecretJSON{Key: "DB", AvailableTo: []string{"FP1", "FP2"}},
			wantContains: []string{`"key":"DB"`, `"available_to":["FP1","FP2"]`},
			wantOmits:    []string{`"deleted"`},
		},
		{
			name:         "deleted secret",
			input:        VaultDescribeSecretJSON{Key: "OLD", Deleted: true},
			wantContains: []string{`"key":"OLD"`, `"deleted":true`},
			wantOmits:    []string{`"available_to"`},
		},
		{
			name:         "secret with no values",
			input:        VaultDescribeSecretJSON{Key: "EMPTY"},
			wantContains: []string{`"key":"EMPTY"`},
			wantOmits:    []string{`"available_to"`, `"deleted"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := string(out)
			for _, sub := range tc.wantContains {
				if !strings.Contains(got, sub) {
					t.Errorf("expected output to contain %q, got: %s", sub, got)
				}
			}
			for _, sub := range tc.wantOmits {
				if strings.Contains(got, sub) {
					t.Errorf("expected output to omit %q, got: %s", sub, got)
				}
			}
		})
	}
}
