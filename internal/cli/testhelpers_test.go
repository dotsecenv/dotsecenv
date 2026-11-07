package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
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

func (m *MockVaultResolver) GetSecretFromAnyVault(key string, stderr io.Writer) (*vault.SecretValue, int, error) {
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
				if len(secret.Values) > 0 && !secret.IsDeleted() {
					return &secret.Values[len(secret.Values)-1], i, nil
				}
			}
		}
	}
	return nil, -1, fmt.Errorf("secret not found")
}

func (m *MockVaultResolver) GetAccessibleSecretFromAnyVault(key, fingerprint string) (*vault.SecretValue, int, error) {
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
				// Reuse the real lookup so the mock walks the same live values.
				v := vault.Vault{Secrets: []vault.Secret{secret}}
				if val := v.GetAccessibleSecretValue(fingerprint, secret.Key); val != nil {
					return val, i, nil
				}
			}
		}
	}
	return nil, -1, fmt.Errorf("secret '%s' not found or not accessible", key)
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

	deleted := -1
	for i := 0; i < count; i++ {
		if secrets, ok := m.Secrets[i]; ok {
			if secret, ok := secrets[key]; ok {
				if !secret.IsDeleted() {
					return i
				}
				if deleted < 0 {
					deleted = i
				}
			}
		}
	}
	return deleted
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

func (m *MockVaultResolver) ListAllSecretKeys() []vault.SecretKeyInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []vault.SecretKeyInfo
	seen := make(map[string]bool)

	count := m.VaultCount()
	for i := 0; i < count; i++ {
		secrets, ok := m.Secrets[i]
		if !ok {
			continue
		}

		vaultPath := ""
		if i < len(m.VaultEntries) {
			vaultPath = m.VaultEntries[i].Path
		} else if i < len(m.VaultPaths) {
			vaultPath = m.VaultPaths[i]
		}

		for key, secret := range secrets {
			if seen[key] {
				continue
			}
			seen[key] = true

			result = append(result, vault.SecretKeyInfo{
				Key:      key,
				Vault:    vaultPath,
				VaultIdx: i + 1,
				Deleted:  secret.IsDeleted(),
			})
		}
	}

	return result
}

func (m *MockVaultResolver) ListSecretKeysFromVault(index int) []vault.SecretKeyInfo {
	m.mu.Lock()
	defer m.mu.Unlock()

	secrets, ok := m.Secrets[index]
	if !ok {
		return nil
	}

	vaultPath := ""
	if index < len(m.VaultEntries) {
		vaultPath = m.VaultEntries[index].Path
	} else if index < len(m.VaultPaths) {
		vaultPath = m.VaultPaths[index]
	}

	var result []vault.SecretKeyInfo
	for key, secret := range secrets {
		result = append(result, vault.SecretKeyInfo{
			Key:      key,
			Vault:    vaultPath,
			VaultIdx: index + 1,
			Deleted:  secret.IsDeleted(),
		})
	}

	return result
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

// newTestSignedLogin builds a *config.Login by running CreateSignedLogin against
// a fresh MockGPGClient. The mock's SignDataWithAgent returns a deterministic
// "signature_by_<fp>" string, so the resulting Login is suitable for tests that
// need a populated Login section without requiring a real GPG keyring.
func newTestSignedLogin(t *testing.T, fingerprint string) *config.Login {
	t.Helper()
	login, err := CreateSignedLogin(NewMockGPGClient(), fingerprint)
	if err != nil {
		t.Fatalf("newTestSignedLogin(%q): %v", fingerprint, err)
	}
	return login
}
