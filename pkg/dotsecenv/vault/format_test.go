package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

func TestNewHeader(t *testing.T) {
	h := NewHeader()
	if h.Version != FormatVersion {
		t.Errorf("expected version %d, got %d", FormatVersion, h.Version)
	}
	if h.Identities == nil {
		t.Error("expected identities map to be initialized")
	}
	if h.Secrets == nil {
		t.Error("expected secrets map to be initialized")
	}
}

func TestHeaderMarshalUnmarshal(t *testing.T) {
	h := &Header{
		Version: LatestFormatVersion,
		Identities: map[string]int{
			"FP1": 5,
			"FP2": 6,
		},
		Secrets: map[string]SecretIndex{
			"SEC1": {Definition: 10, Values: []int{11, 12}},
			"SEC2": {Definition: 20, Values: []int{21}},
		},
	}

	data, err := MarshalHeader(h)
	if err != nil {
		t.Fatalf("MarshalHeader failed: %v", err)
	}

	parsed, err := UnmarshalHeader(data)
	if err != nil {
		t.Fatalf("UnmarshalHeader failed: %v", err)
	}

	if parsed.Version != h.Version {
		t.Errorf("version mismatch: expected %d, got %d", h.Version, parsed.Version)
	}
	if len(parsed.Identities) != len(h.Identities) {
		t.Errorf("identities count mismatch: expected %d, got %d", len(h.Identities), len(parsed.Identities))
	}
	if len(parsed.Secrets) != len(h.Secrets) {
		t.Errorf("secrets count mismatch: expected %d, got %d", len(h.Secrets), len(parsed.Secrets))
	}
}

func TestUnmarshalHeaderEmpty(t *testing.T) {
	data := []byte(`{"version":1}`)
	h, err := UnmarshalHeader(data)
	if err != nil {
		t.Fatalf("UnmarshalHeader failed: %v", err)
	}
	if h.Identities == nil {
		t.Error("expected identities map to be initialized")
	}
	if h.Secrets == nil {
		t.Error("expected secrets map to be initialized")
	}
}

func TestEntryMarshalUnmarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	idData := IdentityData{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}

	jsonData, err := json.Marshal(idData)
	if err != nil {
		t.Fatalf("marshal identity data failed: %v", err)
	}

	entry := Entry{
		Type: EntryTypeIdentity,
		Data: jsonData,
	}

	entryJSON, err := MarshalEntry(entry)
	if err != nil {
		t.Fatalf("MarshalEntry failed: %v", err)
	}

	parsed, err := UnmarshalEntry(entryJSON)
	if err != nil {
		t.Fatalf("UnmarshalEntry failed: %v", err)
	}

	if parsed.Type != entry.Type {
		t.Errorf("type mismatch: expected %s, got %s", entry.Type, parsed.Type)
	}
}

func TestCreateIdentityEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}

	entry, err := CreateIdentityEntry(id)
	if err != nil {
		t.Fatalf("CreateIdentityEntry failed: %v", err)
	}

	if entry.Type != EntryTypeIdentity {
		t.Errorf("expected type %s, got %s", EntryTypeIdentity, entry.Type)
	}

	data, err := ParseIdentityData(entry)
	if err != nil {
		t.Fatalf("ParseIdentityData failed: %v", err)
	}

	if data.Fingerprint != id.Fingerprint {
		t.Errorf("fingerprint mismatch: expected %s, got %s", id.Fingerprint, data.Fingerprint)
	}
}

func TestCreateSecretEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
	}

	entry, err := CreateSecretEntry(s)
	if err != nil {
		t.Fatalf("CreateSecretEntry failed: %v", err)
	}

	if entry.Type != EntryTypeSecret {
		t.Errorf("expected type %s, got %s", EntryTypeSecret, entry.Type)
	}

	data, err := ParseSecretData(entry)
	if err != nil {
		t.Fatalf("ParseSecretData failed: %v", err)
	}

	if data.Key != s.Key {
		t.Errorf("key mismatch: expected %s, got %s", s.Key, data.Key)
	}
}

func TestCreateValueEntry(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	sv := SecretValue{
		AddedAt:     now,
		AvailableTo: []string{"FP1", "FP2"},
		Value:       "encrypted_data",
	}

	entry, err := CreateValueEntry("MY_SECRET", sv)
	if err != nil {
		t.Fatalf("CreateValueEntry failed: %v", err)
	}

	if entry.Type != EntryTypeValue {
		t.Errorf("expected type %s, got %s", EntryTypeValue, entry.Type)
	}
	if entry.SecretKey != "MY_SECRET" {
		t.Errorf("expected secret key MY_SECRET, got %s", entry.SecretKey)
	}

	data, err := ParseValueData(entry)
	if err != nil {
		t.Fatalf("ParseValueData failed: %v", err)
	}

	if data.Value != sv.Value {
		t.Errorf("value mismatch: expected %s, got %s", sv.Value, data.Value)
	}
}

func TestWriterNewVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	if w.IsEmpty() != true {
		t.Error("new vault should be empty")
	}

	// Check file was created with header
	content, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}

	if len(content) == 0 {
		t.Error("vault file should not be empty")
	}
}

func TestWriterAddIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}

	if err := w.AddIdentity(id); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	header := w.Header()
	if len(header.Identities) != 1 {
		t.Errorf("expected 1 identity, got %d", len(header.Identities))
	}
	if _, exists := header.Identities["ABC123"]; !exists {
		t.Error("identity ABC123 not found in header")
	}
}

func TestWriterAddSecret(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
	}

	if err := w.AddSecret(s); err != nil {
		t.Fatalf("AddSecret failed: %v", err)
	}

	header := w.Header()
	if len(header.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(header.Secrets))
	}
	idx, exists := header.Secrets["MY_SECRET"]
	if !exists {
		t.Error("secret MY_SECRET not found in header")
	}
	if len(idx.Values) != 0 {
		t.Errorf("expected 0 values, got %d", len(idx.Values))
	}
}

func TestWriterAddSecretValue(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
	}

	if err := w.AddSecret(s); err != nil {
		t.Fatalf("AddSecret failed: %v", err)
	}

	sv := SecretValue{
		AddedAt:     now,
		AvailableTo: []string{"FP1"},
		Value:       "encrypted_data",
	}

	if err := w.AddSecretValue("MY_SECRET", sv); err != nil {
		t.Fatalf("AddSecretValue failed: %v", err)
	}

	header := w.Header()
	idx := header.Secrets["MY_SECRET"]
	if len(idx.Values) != 1 {
		t.Errorf("expected 1 value, got %d", len(idx.Values))
	}
}

func TestWriterAddSecretWithValues(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "val1"},
			{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1", "FP2"}, Value: "val2"},
		},
	}

	if err := w.AddSecretWithValues(s); err != nil {
		t.Fatalf("AddSecretWithValues failed: %v", err)
	}

	header := w.Header()
	idx := header.Secrets["MY_SECRET"]
	if len(idx.Values) != 2 {
		t.Errorf("expected 2 values, got %d", len(idx.Values))
	}
}

func TestWriterReadVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Add identity
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}
	if err := w.AddIdentity(id); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Add secret with values
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"ABC123"}, Value: "val1"},
		},
	}
	if err := w.AddSecretWithValues(s); err != nil {
		t.Fatalf("AddSecretWithValues failed: %v", err)
	}

	// Read vault back
	vault, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	if len(vault.Identities) != 1 {
		t.Errorf("expected 1 identity, got %d", len(vault.Identities))
	}
	if vault.Identities[0].Fingerprint != "ABC123" {
		t.Errorf("expected fingerprint ABC123, got %s", vault.Identities[0].Fingerprint)
	}

	if len(vault.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(vault.Secrets))
	}
	if vault.Secrets[0].Key != "MY_SECRET" {
		t.Errorf("expected key MY_SECRET, got %s", vault.Secrets[0].Key)
	}
	if len(vault.Secrets[0].Values) != 1 {
		t.Errorf("expected 1 value, got %d", len(vault.Secrets[0].Values))
	}
}

func TestReaderHeader(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create vault with writer
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}
	if err := w.AddIdentity(id); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Read with reader
	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	fingerprints := r.ListIdentityFingerprints()
	if len(fingerprints) != 1 {
		t.Errorf("expected 1 fingerprint, got %d", len(fingerprints))
	}
	if fingerprints[0] != "ABC123" {
		t.Errorf("expected ABC123, got %s", fingerprints[0])
	}
}

func TestReaderGetIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "ECC",
		AlgorithmBits: 256,
		Curve:         "P-256",
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}
	if err := w.AddIdentity(id); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Read
	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	data, err := r.GetIdentity("ABC123")
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}

	if data.Fingerprint != "ABC123" {
		t.Errorf("expected ABC123, got %s", data.Fingerprint)
	}
	if data.Algorithm != "ECC" {
		t.Errorf("expected ECC, got %s", data.Algorithm)
	}
	if data.Curve != "P-256" {
		t.Errorf("expected P-256, got %s", data.Curve)
	}
}

func TestReaderGetSecretValues(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "val1", Hash: "h1"},
			{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1", "FP2"}, Value: "val2", Hash: "h2"},
		},
	}
	if err := w.AddSecretWithValues(s); err != nil {
		t.Fatalf("AddSecretWithValues failed: %v", err)
	}

	// Read
	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	values, err := r.GetSecretValues("MY_SECRET")
	if err != nil {
		t.Fatalf("GetSecretValues failed: %v", err)
	}

	if len(values) != 2 {
		t.Errorf("expected 2 values, got %d", len(values))
	}
	if values[0].Value != "val1" {
		t.Errorf("expected val1, got %s", values[0].Value)
	}
	if values[1].Value != "val2" {
		t.Errorf("expected val2, got %s", values[1].Value)
	}
}

func TestWriterDuplicateIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}

	if err := w.AddIdentity(id); err != nil {
		t.Fatalf("first AddIdentity failed: %v", err)
	}

	// Should fail on duplicate
	err = w.AddIdentity(id)
	if err == nil {
		t.Error("expected error for duplicate identity")
	}
}

func TestWriterDuplicateSecret(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "FP1",
	}

	if err := w.AddSecret(s); err != nil {
		t.Fatalf("first AddSecret failed: %v", err)
	}

	// Should fail on duplicate
	err = w.AddSecret(s)
	if err == nil {
		t.Error("expected error for duplicate secret")
	}
}

func TestReaderEmptyVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create an empty file
	f, err := os.Create(vaultPath)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	_ = f.Close()

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	// Should have empty header
	if len(r.ListIdentityFingerprints()) != 0 {
		t.Error("expected no identities")
	}
	if len(r.ListSecretKeys()) != 0 {
		t.Error("expected no secrets")
	}
}

func TestReaderNonExistentVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "nonexistent")

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed for nonexistent file: %v", err)
	}

	// Should have empty header
	if len(r.ListIdentityFingerprints()) != 0 {
		t.Error("expected no identities")
	}
}

func TestReaderHasIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:     now,
		Fingerprint: "ABC123",
	}
	if err := w.AddIdentity(id); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if !r.HasIdentity("ABC123") {
		t.Error("expected HasIdentity to return true for ABC123")
	}
	if r.HasIdentity("XYZ789") {
		t.Error("expected HasIdentity to return false for XYZ789")
	}
}

func TestReaderHasSecret(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	s := Secret{AddedAt: now, Key: "MY_SECRET"}
	if err := w.AddSecret(s); err != nil {
		t.Fatalf("AddSecret failed: %v", err)
	}

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if !r.HasSecret("MY_SECRET") {
		t.Error("expected HasSecret to return true for MY_SECRET")
	}
	if r.HasSecret("OTHER") {
		t.Error("expected HasSecret to return false for OTHER")
	}
}

func TestWriterReload(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w1, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:     now,
		Fingerprint: "ABC123",
	}
	if err := w1.AddIdentity(id); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Create second writer and reload
	w2, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("second NewWriter failed: %v", err)
	}

	header := w2.Header()
	if _, exists := header.Identities["ABC123"]; !exists {
		t.Error("expected ABC123 in reloaded header")
	}
}

func TestWriterRewriteFromVault(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	vault := Vault{
		Identities: []identity.Identity{
			{AddedAt: now, Fingerprint: "FP1"},
			{AddedAt: now.Add(time.Second), Fingerprint: "FP2"},
		},
		Secrets: []Secret{
			{
				AddedAt: now,
				Key:     "SEC1",
				Values: []SecretValue{
					{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
				},
			},
		},
	}

	if err := w.RewriteFromVault(vault); err != nil {
		t.Fatalf("RewriteFromVault failed: %v", err)
	}

	// Verify
	readVault, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	if len(readVault.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(readVault.Identities))
	}
	if len(readVault.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(readVault.Secrets))
	}
}

func TestDefragmentation(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Add identities and secrets in non-optimal order
	// Add identity
	id1 := identity.Identity{AddedAt: now, Fingerprint: "FP1"}
	if err := w.AddIdentity(id1); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Add secret
	s1 := Secret{AddedAt: now, Key: "SEC1"}
	if err := w.AddSecret(s1); err != nil {
		t.Fatalf("AddSecret failed: %v", err)
	}

	// Add another identity (fragmenting identities)
	id2 := identity.Identity{AddedAt: now.Add(time.Second), Fingerprint: "FP2"}
	if err := w.AddIdentity(id2); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Add value to first secret (fragmenting secret from its value)
	sv := SecretValue{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"}
	if err := w.AddSecretValue("SEC1", sv); err != nil {
		t.Fatalf("AddSecretValue failed: %v", err)
	}

	// Get stats before defrag
	r, _ := NewReader(vaultPath)
	statsBefore, _ := CalculateFragmentation(r)

	// Defragment
	statsAfter, err := Defragment(w)
	if err != nil {
		t.Fatalf("Defragment failed: %v", err)
	}

	// After defragmentation, fragmentation should be 0 or very low
	t.Logf("Before: fragmentation=%.2f, spread=%.2f", statsBefore.FragmentationRatio, statsBefore.AverageSecretSpread)
	t.Logf("After: fragmentation=%.2f, spread=%.2f", statsAfter.FragmentationRatio, statsAfter.AverageSecretSpread)

	// Verify vault is still valid
	vault, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault after defrag failed: %v", err)
	}

	if len(vault.Identities) != 2 {
		t.Errorf("expected 2 identities after defrag, got %d", len(vault.Identities))
	}
	if len(vault.Secrets) != 1 {
		t.Errorf("expected 1 secret after defrag, got %d", len(vault.Secrets))
	}
}

func TestDefragmentationOptimalOrder(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// Create vault with multiple secrets and values
	vault := Vault{
		Identities: []identity.Identity{
			{AddedAt: now.Add(time.Second), Fingerprint: "FP2"}, // Out of order
			{AddedAt: now, Fingerprint: "FP1"},
		},
		Secrets: []Secret{
			{
				AddedAt: now,
				Key:     "ZZZ", // Will sort last
				Values: []SecretValue{
					{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1"}, Value: "v2"}, // Out of order
					{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
				},
			},
			{
				AddedAt: now,
				Key:     "AAA", // Will sort first
				Values:  []SecretValue{},
			},
		},
	}

	if err := w.RewriteFromVault(vault); err != nil {
		t.Fatalf("RewriteFromVault failed: %v", err)
	}

	// Defragment
	_, err = Defragment(w)
	if err != nil {
		t.Fatalf("Defragment failed: %v", err)
	}

	// Read and verify order
	readVault, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	// Verify identities exist (order in returned slice may vary due to map iteration)
	if len(readVault.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(readVault.Identities))
	}

	// Verify both fingerprints are present
	fpFound := make(map[string]bool)
	for _, id := range readVault.Identities {
		fpFound[id.Fingerprint] = true
	}
	if !fpFound["FP1"] || !fpFound["FP2"] {
		t.Error("missing expected fingerprints after defrag")
	}

	// Secrets should be sorted by key
	if len(readVault.Secrets) >= 2 {
		if readVault.Secrets[0].Key >= readVault.Secrets[1].Key {
			t.Errorf("secrets not sorted by key: %s >= %s", readVault.Secrets[0].Key, readVault.Secrets[1].Key)
		}
	}

	// First secret should be AAA, second ZZZ
	if readVault.Secrets[0].Key != "AAA" {
		t.Errorf("expected first secret to be AAA, got %s", readVault.Secrets[0].Key)
	}
	if readVault.Secrets[1].Key != "ZZZ" {
		t.Errorf("expected second secret to be ZZZ, got %s", readVault.Secrets[1].Key)
	}

	// ZZZ secret values should be sorted by AddedAt
	zzzSecret := readVault.Secrets[1]
	if len(zzzSecret.Values) >= 2 {
		if !zzzSecret.Values[0].AddedAt.Before(zzzSecret.Values[1].AddedAt) {
			t.Error("secret values not sorted by AddedAt after defrag")
		}
	}
}

func TestFragmentationStats(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Small vault - should never recommend defrag
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 10; i++ {
		id := identity.Identity{AddedAt: now.Add(time.Duration(i) * time.Second), Fingerprint: string(rune('A' + i))}
		if err := w.AddIdentity(id); err != nil {
			t.Fatalf("AddIdentity failed: %v", err)
		}
	}

	r, _ := NewReader(vaultPath)
	stats, err := CalculateFragmentation(r)
	if err != nil {
		t.Fatalf("CalculateFragmentation failed: %v", err)
	}

	if stats.TotalEntries != 10 {
		t.Errorf("expected 10 entries, got %d", stats.TotalEntries)
	}
	if stats.RecommendDefrag {
		t.Error("small vault should not recommend defragmentation")
	}
}
