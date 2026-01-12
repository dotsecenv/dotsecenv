package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// MockVaultResolver is a mock implementation of VaultResolver interface
type MockVaultResolver struct {
	mu                sync.Mutex
	Identities        map[string]vault.Identity
	IdentitiesByVault map[int]map[string]vault.Identity // index -> fingerprint -> identity
	Secrets           map[int]map[string]vault.Secret   // index -> key -> secret
	VaultPaths        []string                          // List of vault paths
	AddSecretFunc     func(secret vault.Secret, index int) error
	SavedVaults       []int // Track which vaults (indices) were saved
	VaultEntries      []vault.VaultEntry
	Managers          map[int]*vault.Manager // Optional managers for tests that need them
}

func NewMockVaultResolver() *MockVaultResolver {
	return &MockVaultResolver{
		Identities:        make(map[string]vault.Identity),
		IdentitiesByVault: make(map[int]map[string]vault.Identity),
		Secrets:           make(map[int]map[string]vault.Secret),
		SavedVaults:       []int{},
	}
}

func (m *MockVaultResolver) GetIdentityByFingerprint(fingerprint string) *vault.Identity {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.Identities[fingerprint]
	if !ok {
		return nil
	}
	return &id
}

func (m *MockVaultResolver) AddSecret(secret vault.Secret, index int) error {
	if m.AddSecretFunc != nil {
		return m.AddSecretFunc(secret, index)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.Secrets[index]; !ok {
		m.Secrets[index] = make(map[string]vault.Secret)
	}
	m.Secrets[index][secret.Key] = secret
	return nil
}

func (m *MockVaultResolver) AddIdentity(identity vault.Identity, index int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Identities[identity.Fingerprint] = identity

	if index >= 0 {
		if _, ok := m.IdentitiesByVault[index]; !ok {
			m.IdentitiesByVault[index] = make(map[string]vault.Identity)
		}
		m.IdentitiesByVault[index][identity.Fingerprint] = identity
	}
	return nil
}

func (m *MockVaultResolver) SaveAll() error {
	return nil
}

func (m *MockVaultResolver) CloseAll() error {
	return nil
}

func (m *MockVaultResolver) GetSecretFromAnyVault(key string, stderr io.Writer) (*vault.SecretValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Search in order
	count := len(m.VaultPaths)
	if len(m.VaultEntries) > count {
		count = len(m.VaultEntries)
	}

	for i := 0; i < count; i++ {
		if secrets, ok := m.Secrets[i]; ok {
			if secret, ok := secrets[key]; ok {
				if len(secret.Values) > 0 {
					return &secret.Values[len(secret.Values)-1], nil
				}
			}
		}
	}
	return nil, fmt.Errorf("secret not found")
}

func (m *MockVaultResolver) GetAccessibleSecretFromAnyVault(key, fingerprint string, strict bool) (*vault.SecretValue, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Search in order
	count := len(m.VaultPaths)
	if len(m.VaultEntries) > count {
		count = len(m.VaultEntries)
	}

	for i := 0; i < count; i++ {
		if secrets, ok := m.Secrets[i]; ok {
			if secret, ok := secrets[key]; ok {
				if len(secret.Values) == 0 {
					continue
				}

				// In strict mode, only check the latest value
				if strict {
					latestValue := &secret.Values[len(secret.Values)-1]
					for _, fp := range latestValue.AvailableTo {
						if fp == fingerprint {
							return latestValue, nil
						}
					}
					continue
				}

				// Non-strict: check from most recent to oldest for accessible value
				for j := len(secret.Values) - 1; j >= 0; j-- {
					for _, fp := range secret.Values[j].AvailableTo {
						if fp == fingerprint {
							return &secret.Values[j], nil
						}
					}
				}
			}
		}
	}
	return nil, fmt.Errorf("secret '%s' not found or not accessible", key)
}

func (m *MockVaultResolver) GetSecretByKeyFromVault(index int, key string) *vault.Secret {
	m.mu.Lock()
	defer m.mu.Unlock()
	if secrets, ok := m.Secrets[index]; ok {
		if secret, ok := secrets[key]; ok {
			return &secret
		}
	}
	return nil
}

func (m *MockVaultResolver) FindSecretVaultIndex(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := len(m.VaultPaths)
	if len(m.VaultEntries) > count {
		count = len(m.VaultEntries)
	}

	for i := 0; i < count; i++ {
		if secrets, ok := m.Secrets[i]; ok {
			if _, ok := secrets[key]; ok {
				return i
			}
		}
	}
	return -1
}

func (m *MockVaultResolver) GetVaultManager(index int) *vault.Manager {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Managers != nil {
		return m.Managers[index]
	}
	return nil // Mock returns nil manager usually, but tests might need to mock this if they call methods on manager
}

func (m *MockVaultResolver) GetConfig() vault.VaultConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return vault.VaultConfig{Entries: m.VaultEntries}
}

func (m *MockVaultResolver) GetVaultPaths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.VaultPaths
}

func (m *MockVaultResolver) GetAvailableVaultPathsWithIndices() []vault.VaultPathWithIndex {
	m.mu.Lock()
	defer m.mu.Unlock()
	// In mock, all configured vaults are considered available
	var result []vault.VaultPathWithIndex
	for i, path := range m.VaultPaths {
		result = append(result, vault.VaultPathWithIndex{Path: path, Index: i})
	}
	return result
}

func (m *MockVaultResolver) IsPathInConfig(path string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.VaultPaths {
		if vault.ExpandPath(p) == vault.ExpandPath(path) {
			return true
		}
	}
	return false
}

func (m *MockVaultResolver) IdentityExistsInVault(fingerprint string, index int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mapV, ok := m.IdentitiesByVault[index]; ok {
		_, exists := mapV[fingerprint]
		return exists
	}
	return false
}

func (m *MockVaultResolver) SaveVault(index int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SavedVaults = append(m.SavedVaults, index)
	return nil
}

func (m *MockVaultResolver) GetLoadError(index int) error {
	return nil
}

func (m *MockVaultResolver) GetSecret(index int, key string) (*vault.SecretValue, error) {
	s := m.GetSecretByKeyFromVault(index, key)
	if s == nil || len(s.Values) == 0 {
		return nil, fmt.Errorf("not found")
	}
	return &s.Values[len(s.Values)-1], nil
}

func (m *MockVaultResolver) OpenVaultsFromPaths(paths []string, stderr io.Writer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.VaultPaths = paths
	// Rebuild entries
	m.VaultEntries = nil
	for _, p := range paths {
		m.VaultEntries = append(m.VaultEntries, vault.VaultEntry{Path: p})
	}
	return nil
}

func (m *MockVaultResolver) OpenVaults(stderr io.Writer) error {
	return nil
}

func (m *MockVaultResolver) VaultCount() int {
	count := len(m.VaultPaths)
	if len(m.VaultEntries) > count {
		count = len(m.VaultEntries)
	}
	// Also count from Secrets map
	for idx := range m.Secrets {
		if idx+1 > count {
			count = idx + 1
		}
	}
	return count
}

// MockGPGClient is a mock implementation of GPGClient interface
type MockGPGClient struct {
	PublicKeyInfo map[string]gpg.KeyInfo
}

func NewMockGPGClient() *MockGPGClient {
	return &MockGPGClient{
		PublicKeyInfo: make(map[string]gpg.KeyInfo),
	}
}

func (m *MockGPGClient) GetPublicKeyInfo(fingerprint string) (*gpg.KeyInfo, error) {
	if info, ok := m.PublicKeyInfo[fingerprint]; ok {
		return &info, nil
	}
	return nil, fmt.Errorf("public key info not found for %s", fingerprint)
}

func (m *MockGPGClient) EncryptToRecipients(plaintext []byte, recipients []string, signingKey *crypto.Key) (string, error) {
	return fmt.Sprintf("encrypted_to_%s_%s", strings.Join(recipients, "_"), string(plaintext)), nil
}

func (m *MockGPGClient) SignDataWithAgent(fingerprint string, data []byte) (string, error) {
	return fmt.Sprintf("signature_by_%s", fingerprint), nil
}

func (m *MockGPGClient) DecryptWithAgent(ciphertext []byte, fingerprint string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *MockGPGClient) ExtractAlgorithmAndCurve(fullAlgorithm string) (algorithm string, curve string) {
	return fullAlgorithm, ""
}

func (m *MockGPGClient) GetKeyCreationTime(fingerprint string) time.Time {
	return time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
}

func (m *MockGPGClient) SignIdentity(identity *vault.Identity, signerFingerprint string) (hash string, signature string, err error) {
	return "mock_hash", "mock_signature", nil
}

func (m *MockGPGClient) SignSecret(secret *vault.Secret, signerFingerprint string, algorithmBits int) (hash string, signature string, err error) {
	return "mock_hash", "mock_signature", nil
}

func (m *MockGPGClient) SignSecretValue(value *vault.SecretValue, secretKey string, signerFingerprint string, algorithmBits int) (hash string, signature string, err error) {
	return "mock_hash", "mock_signature", nil
}

func (m *MockGPGClient) DecryptSecret(encryptedBase64 string, fingerprint string) ([]byte, error) {
	return []byte("decrypted_secret"), nil
}

func (m *MockGPGClient) DecryptSecretValue(value *vault.SecretValue, fingerprint string) ([]byte, error) {
	return []byte("decrypted_secret_value"), nil
}

func (m *MockGPGClient) IsAgentAvailable() bool {
	return true
}

func (m *MockGPGClient) ListSecretKeys() ([]gpg.SecretKeyInfo, error) {
	return []gpg.SecretKeyInfo{
		{Fingerprint: "TESTFINGERPRINT", UID: "Test User <test@example.com>"},
	}, nil
}

// TestSecretPut_WithVaultPath tests the -v flag functionality
func TestSecretPut_WithVaultPath(t *testing.T) {
	t.Setenv("DOTSECENV_FINGERPRINT", "") // Clear env to use mock config fingerprint
	t.Setenv("DOTSECENV_CONFIG", "")      // Clear env to avoid config pollution

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
		Fingerprint: testFP,
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
	putErr := cli.SecretPut("MY_SECRET", vaultPath, 0)
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
	t.Setenv("DOTSECENV_FINGERPRINT", "") // Clear env to use mock config fingerprint
	t.Setenv("DOTSECENV_CONFIG", "")      // Clear env to avoid config pollution

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
		Fingerprint: testFP,
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
	err := cli.SecretPut("MY_SECRET", "", 2)
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
		Fingerprint: testFP,
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
	err := cli.SecretPut("MY_SECRET", "", 4)
	if err == nil {
		t.Fatalf("Expected SecretPut with -v 4 to fail, but it succeeded")
	}

	if !strings.Contains(err.Message, "-v index 4 exceeds number of configured vaults") {
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
	t.Setenv("DOTSECENV_FINGERPRINT", "") // Clear env to use mock config fingerprint
	t.Setenv("DOTSECENV_CONFIG", "")      // Clear env to avoid config pollution

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
		Fingerprint: testFP,
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
	t.Setenv("DOTSECENV_FINGERPRINT", "")
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
		Fingerprint: testFP,
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
	forgetErr := cli.SecretForget("MY_SECRET", vaultPath, 0)
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
	t.Setenv("DOTSECENV_FINGERPRINT", "")
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
		Fingerprint: testFP,
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
	forgetErr := cli.SecretForget("MY_SECRET", vaultPath, 0)
	if forgetErr == nil {
		t.Fatal("SecretForget should fail for already-deleted secret")
	}

	if !strings.Contains(forgetErr.Message, "already deleted") {
		t.Errorf("Expected 'already deleted' error, got: %s", forgetErr.Message)
	}
}

// TestSecretForget_NotFound tests that forgetting a non-existent secret fails
func TestSecretForget_NotFound(t *testing.T) {
	t.Setenv("DOTSECENV_FINGERPRINT", "")
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
		Fingerprint: testFP,
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
	forgetErr := cli.SecretForget("NONEXISTENT", vaultPath, 0)
	if forgetErr == nil {
		t.Fatal("SecretForget should fail for non-existent secret")
	}

	if !strings.Contains(forgetErr.Message, "not found") {
		t.Errorf("Expected 'not found' error, got: %s", forgetErr.Message)
	}
}

// TestSecretPut_BlockedByDeleted tests that putting to a deleted secret fails
func TestSecretPut_BlockedByDeleted(t *testing.T) {
	t.Setenv("DOTSECENV_FINGERPRINT", "")
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
		Fingerprint: testFP,
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
	putErr := cli.SecretPut("DELETED_SECRET", vaultPath, 0)
	if putErr == nil {
		t.Fatal("SecretPut should fail for deleted secret")
	}

	if !strings.Contains(putErr.Message, "has been deleted") {
		t.Errorf("Expected 'has been deleted' error, got: %s", putErr.Message)
	}

	if !strings.Contains(putErr.Message, "cannot overwrite") {
		t.Errorf("Expected 'cannot overwrite' in error, got: %s", putErr.Message)
	}
}

// TestSecretForget_NoAccess tests that forgetting without access fails
func TestSecretForget_NoAccess(t *testing.T) {
	t.Setenv("DOTSECENV_FINGERPRINT", "")
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
		Fingerprint: testFP,
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
	forgetErr := cli.SecretForget("OTHER_SECRET", vaultPath, 0)
	if forgetErr == nil {
		t.Fatal("SecretForget should fail without access")
	}

	if !strings.Contains(forgetErr.Message, "access denied") {
		t.Errorf("Expected 'access denied' error, got: %s", forgetErr.Message)
	}
}
