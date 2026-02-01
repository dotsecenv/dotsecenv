package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

func TestManagerBasicWorkflow(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	// Add identity
	now := time.Now().UTC().Truncate(time.Second)
	id := identity.Identity{
		AddedAt:       now,
		Algorithm:     "RSA",
		AlgorithmBits: 4096,
		Fingerprint:   "ABC123",
		UID:           "test@example.com",
	}
	m.AddIdentity(id)

	// Add secret
	s := Secret{
		AddedAt:  now,
		Key:      "MY_SECRET",
		Hash:     "hash123",
		SignedBy: "ABC123",
		Values: []SecretValue{
			{
				AddedAt:     now,
				AvailableTo: []string{"ABC123"},
				Value:       "encrypted_value",
				Hash:        "vhash",
			},
		},
	}
	m.AddSecret(s)

	// Verify
	vault := m.Get()
	if len(vault.Identities) != 1 {
		t.Errorf("expected 1 identity, got %d", len(vault.Identities))
	}
	if len(vault.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(vault.Secrets))
	}

	// Test access
	if !m.CanIdentityAccessSecret("ABC123", "MY_SECRET") {
		t.Error("expected ABC123 to access MY_SECRET")
	}
	if m.CanIdentityAccessSecret("XYZ789", "MY_SECRET") {
		t.Error("expected XYZ789 to NOT access MY_SECRET")
	}
}

func TestManagerPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// First manager: add data
	m1 := NewManager(vaultPath, false)
	if err := m1.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	m1.AddIdentity(identity.Identity{
		AddedAt:     now,
		Fingerprint: "FP1",
	})
	m1.AddSecret(Secret{
		AddedAt: now,
		Key:     "SEC1",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
		},
	})

	if err := m1.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if err := m1.Unlock(); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Second manager: verify data persisted
	m2 := NewManager(vaultPath, false)
	if err := m2.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m2.Unlock() }()

	vault := m2.Get()
	if len(vault.Identities) != 1 {
		t.Errorf("expected 1 identity, got %d", len(vault.Identities))
	}
	if len(vault.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(vault.Secrets))
	}
	if vault.Secrets[0].Key != "SEC1" {
		t.Errorf("expected SEC1, got %s", vault.Secrets[0].Key)
	}
}

func TestManagerAddSecretValues(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	now := time.Now().UTC().Truncate(time.Second)

	// Add initial secret
	m.AddSecret(Secret{
		AddedAt: now,
		Key:     "MY_SECRET",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
		},
	})

	// Add more values to same secret
	m.AddSecret(Secret{
		Key: "MY_SECRET",
		Values: []SecretValue{
			{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1", "FP2"}, Value: "v2"},
		},
	})

	// Verify
	secret := m.GetSecretByKey("MY_SECRET")
	if secret == nil {
		t.Fatal("secret not found")
	}
	if len(secret.Values) != 2 {
		t.Errorf("expected 2 values, got %d", len(secret.Values))
	}
}

func TestManagerGetAccessibleSecretValue(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	now := time.Now().UTC().Truncate(time.Second)

	// Add secret with multiple values
	m.AddSecret(Secret{
		AddedAt: now,
		Key:     "MY_SECRET",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},                  // FP1 only
			{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP2"}, Value: "v2"}, // FP2 only
		},
	})

	// FP1 should get v1 (falls back to most recent they can access)
	val := m.GetAccessibleSecretValue("FP1", "MY_SECRET")
	if val == nil {
		t.Fatal("expected value for FP1")
	}
	if val.Value != "v1" {
		t.Errorf("expected v1, got %s", val.Value)
	}

	// FP2 can access latest (v2)
	val = m.GetAccessibleSecretValue("FP2", "MY_SECRET")
	if val == nil {
		t.Fatal("expected value for FP2")
	}
	if val.Value != "v2" {
		t.Errorf("expected v2, got %s", val.Value)
	}

	// FP3 has no access
	val = m.GetAccessibleSecretValue("FP3", "MY_SECRET")
	if val != nil {
		t.Error("expected nil for FP3 (no access)")
	}
}

func TestManagerListMethods(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	now := time.Now().UTC().Truncate(time.Second)

	// Add some identities
	m.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP2"})
	m.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"})

	// Add some secrets
	m.AddSecret(Secret{AddedAt: now, Key: "SEC2"})
	m.AddSecret(Secret{AddedAt: now, Key: "SEC1"})

	// List fingerprints
	fps := m.ListIdentityFingerprints()
	if len(fps) != 2 {
		t.Errorf("expected 2 fingerprints, got %d", len(fps))
	}

	// List keys (should be sorted)
	keys := m.ListSecretKeys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	if keys[0] != "SEC1" {
		t.Errorf("expected SEC1 first, got %s", keys[0])
	}
}

func TestManagerFragmentationStats(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	now := time.Now().UTC().Truncate(time.Second)

	// Add some data
	for i := 0; i < 5; i++ {
		m.AddIdentity(identity.Identity{
			AddedAt:     now.Add(time.Duration(i) * time.Second),
			Fingerprint: fmt.Sprintf("FP%d", i),
		})
	}

	stats, err := m.FragmentationStats()
	if err != nil {
		t.Fatalf("FragmentationStats failed: %v", err)
	}

	if stats.TotalEntries != 5 {
		t.Errorf("expected 5 entries, got %d", stats.TotalEntries)
	}
}

func TestManagerDefragment(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	now := time.Now().UTC().Truncate(time.Second)

	// Add data in fragmented order
	m.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"})
	m.AddSecret(Secret{AddedAt: now, Key: "SEC1"})
	m.AddIdentity(identity.Identity{AddedAt: now.Add(time.Second), Fingerprint: "FP2"})

	// Add value to secret (causes fragmentation)
	m.AddSecret(Secret{
		Key: "SEC1",
		Values: []SecretValue{
			{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
		},
	})

	// Defragment
	stats, err := m.Defragment()
	if err != nil {
		t.Fatalf("Defragment failed: %v", err)
	}

	t.Logf("After defrag: entries=%d, fragmentation=%.2f", stats.TotalEntries, stats.FragmentationRatio)

	// Verify data still accessible
	vault := m.Get()
	if len(vault.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(vault.Identities))
	}
	if len(vault.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(vault.Secrets))
	}
}

// Race condition tests

func TestWriterConcurrentReads(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Setup vault with data
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 10; i++ {
		if err := w.AddIdentity(identity.Identity{
			AddedAt:     now.Add(time.Duration(i) * time.Second),
			Fingerprint: fmt.Sprintf("FP%d", i),
		}); err != nil {
			t.Fatalf("AddIdentity failed: %v", err)
		}
	}

	// Concurrent reads
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := NewReader(vaultPath)
			if err != nil {
				errors <- err
				return
			}
			fps := r.ListIdentityFingerprints()
			if len(fps) != 10 {
				errors <- fmt.Errorf("expected 10 fingerprints, got %d", len(fps))
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent read error: %v", err)
	}
}

func TestHeaderMarshalRace(t *testing.T) {
	// Test that header marshaling doesn't have race conditions
	h := &Header{
		Version:    1,
		Identities: make(map[string]int),
		Secrets:    make(map[string]SecretIndex),
	}

	// Add some data
	for i := 0; i < 100; i++ {
		h.Identities[fmt.Sprintf("FP%d", i)] = i + 10
		h.Secrets[fmt.Sprintf("SEC%d", i)] = SecretIndex{
			Definition: i + 100,
			Values:     []int{i + 200, i + 201},
		}
	}

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent marshaling (read-only operations)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := MarshalHeader(h)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("marshal race error: %v", err)
	}
}

func TestEntryParsingRace(t *testing.T) {
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

	entryJSON, err := MarshalEntry(*entry)
	if err != nil {
		t.Fatalf("MarshalEntry failed: %v", err)
	}

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent parsing
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			parsed, err := UnmarshalEntry(entryJSON)
			if err != nil {
				errors <- err
				return
			}
			_, err = ParseIdentityData(parsed)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("parsing race error: %v", err)
	}
}

func TestReaderConcurrentLineReads(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Setup vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 20; i++ {
		if err := w.AddIdentity(identity.Identity{
			AddedAt:     now.Add(time.Duration(i) * time.Second),
			Fingerprint: fmt.Sprintf("FP%02d", i),
		}); err != nil {
			t.Fatalf("AddIdentity failed: %v", err)
		}
	}

	// Multiple readers reading different entries concurrently
	var wg sync.WaitGroup
	errors := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		fp := fmt.Sprintf("FP%02d", i)
		go func(fingerprint string) {
			defer wg.Done()
			r, err := NewReader(vaultPath)
			if err != nil {
				errors <- fmt.Errorf("NewReader failed: %w", err)
				return
			}

			id, err := r.GetIdentity(fingerprint)
			if err != nil {
				errors <- fmt.Errorf("GetIdentity(%s) failed: %w", fingerprint, err)
				return
			}

			if id.Fingerprint != fingerprint {
				errors <- fmt.Errorf("fingerprint mismatch: expected %s, got %s", fingerprint, id.Fingerprint)
			}
		}(fp)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent line read error: %v", err)
	}
}

// Benchmark tests

func BenchmarkWriterAddIdentity(b *testing.B) {
	tmpDir := b.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		b.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := identity.Identity{
			AddedAt:       now.Add(time.Duration(i) * time.Second),
			Fingerprint:   fmt.Sprintf("FP%d", i),
			Algorithm:     "RSA",
			AlgorithmBits: 4096,
		}
		if err := w.AddIdentity(id); err != nil {
			b.Fatalf("AddIdentity failed: %v", err)
		}
	}
}

func BenchmarkReaderGetIdentity(b *testing.B) {
	tmpDir := b.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Setup vault with 1000 identities
	w, err := NewWriter(vaultPath)
	if err != nil {
		b.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 1000; i++ {
		if err := w.AddIdentity(identity.Identity{
			AddedAt:     now.Add(time.Duration(i) * time.Second),
			Fingerprint: fmt.Sprintf("FP%04d", i),
		}); err != nil {
			b.Fatalf("AddIdentity failed: %v", err)
		}
	}

	r, err := NewReader(vaultPath)
	if err != nil {
		b.Fatalf("NewReader failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fp := fmt.Sprintf("FP%04d", i%1000)
		_, err := r.GetIdentity(fp)
		if err != nil {
			b.Fatalf("GetIdentity failed: %v", err)
		}
	}
}

func BenchmarkHeaderMarshal(b *testing.B) {
	h := &Header{
		Version:    1,
		Identities: make(map[string]int),
		Secrets:    make(map[string]SecretIndex),
	}

	// Populate with 1000 entries
	for i := 0; i < 1000; i++ {
		h.Identities[fmt.Sprintf("FP%04d", i)] = i + 10
	}
	for i := 0; i < 100; i++ {
		h.Secrets[fmt.Sprintf("SEC%04d", i)] = SecretIndex{
			Definition: i + 2000,
			Values:     []int{i + 3000, i + 3001, i + 3002},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := MarshalHeader(h)
		if err != nil {
			b.Fatalf("MarshalHeader failed: %v", err)
		}
	}
}

func BenchmarkDefragment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tmpDir := b.TempDir()
		vaultPath := filepath.Join(tmpDir, "vault")

		w, err := NewWriter(vaultPath)
		if err != nil {
			b.Fatalf("NewWriter failed: %v", err)
		}

		// Create fragmented vault
		now := time.Now().UTC().Truncate(time.Second)
		for j := 0; j < 100; j++ {
			_ = w.AddIdentity(identity.Identity{
				AddedAt:     now.Add(time.Duration(j) * time.Second),
				Fingerprint: fmt.Sprintf("FP%03d", j),
			})
			_ = w.AddSecret(Secret{AddedAt: now, Key: fmt.Sprintf("SEC%03d", j)})
		}

		b.StartTimer()
		_, err = Defragment(w)
		if err != nil {
			b.Fatalf("Defragment failed: %v", err)
		}
	}
}

// Error handling tests

func TestReaderInvalidHeader(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Write invalid content
	if err := os.WriteFile(vaultPath, []byte("not a valid header\n{broken json\n"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := NewReader(vaultPath)
	if err == nil {
		t.Error("expected error for invalid header")
	}
}

func TestReaderMissingEntry(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	// Try to get non-existent identity
	_, err = r.GetIdentity("NONEXISTENT")
	if err == nil {
		t.Error("expected error for non-existent identity")
	}
}

func TestWriterAddValueToNonExistentSecret(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	sv := SecretValue{AddedAt: now, Value: "test"}

	err = w.AddSecretValue("NONEXISTENT", sv)
	if err == nil {
		t.Error("expected error for adding value to non-existent secret")
	}
}
