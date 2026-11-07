package vault

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// appendHistory writes identities FP1 and FP2 and then each value of key, one
// append at a time, through the same Manager path 'secret store' and 'secret
// forget' use.
func appendHistory(t *testing.T, path, key string, values ...SecretValue) {
	t.Helper()
	m := NewManager(path, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock(%s): %v", path, err)
	}
	defer func() { _ = m.Unlock() }()

	base := values[0].AddedAt
	m.AddIdentity(identity.Identity{AddedAt: base, Fingerprint: "FP1"})
	m.AddIdentity(identity.Identity{AddedAt: base, Fingerprint: "FP2"})
	for _, v := range values {
		m.AddSecret(Secret{AddedAt: base, Key: key, SignedBy: "FP1", Values: []SecretValue{v}})
	}
}

// history builds values one second apart, ending an hour in the past so the
// append-time clock checks accept them.
func history(entries ...SecretValue) []SecretValue {
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for i := range entries {
		entries[i].AddedAt = start.Add(time.Duration(i) * time.Second)
		entries[i].SignedBy = "FP1"
	}
	return entries
}

func openResolver(t *testing.T, paths ...string) *VaultResolver {
	t.Helper()
	cfg := VaultConfig{}
	for _, p := range paths {
		cfg.Entries = append(cfg.Entries, VaultEntry{Path: p})
	}
	r := NewVaultResolver(cfg)
	if err := r.OpenVaults(&bytes.Buffer{}); err != nil {
		t.Fatalf("OpenVaults: %v", err)
	}
	t.Cleanup(func() { _ = r.CloseAll() })
	return r
}

func tombstone() SecretValue {
	return SecretValue{AvailableTo: []string{}, Deleted: true}
}

func TestSecret_LiveStart(t *testing.T) {
	v := func(deleted bool) SecretValue { return SecretValue{Deleted: deleted} }
	tests := []struct {
		name   string
		values []SecretValue
		want   int
	}{
		{"no values", nil, 0},
		{"never deleted", []SecretValue{v(false), v(false)}, 0},
		{"deleted", []SecretValue{v(false), v(true)}, 2},
		{"stored after deletion", []SecretValue{v(false), v(true), v(false)}, 2},
		{"deleted twice", []SecretValue{v(false), v(true), v(false), v(true), v(false)}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Secret{Values: tt.values}
			if got := s.LiveStart(); got != tt.want {
				t.Errorf("LiveStart() = %d, want %d", got, tt.want)
			}
			if got := len(s.LiveValues()); got != len(tt.values)-tt.want {
				t.Errorf("len(LiveValues()) = %d, want %d", got, len(tt.values)-tt.want)
			}
		})
	}
}

// A value stored after a deletion starts the secret over: nothing before the
// deletion is returned, counted as access, or kept by compaction.
func TestStoreAfterDelete_ReadsStopAtDeletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	appendHistory(t, path, "SEC", history(
		SecretValue{AvailableTo: []string{"FP1", "FP2"}, Value: "v1"},
		tombstone(),
		SecretValue{AvailableTo: []string{"FP1"}, Value: "v2"},
	)...)

	r := openResolver(t, path)

	val, idx, err := r.GetAccessibleSecretFromAnyVault("SEC", "FP1")
	if err != nil || val.Value != "v2" || idx != 0 {
		t.Fatalf("FP1 get = (%v, %d, %v), want v2 from vault 0", val, idx, err)
	}
	if val, _, err := r.GetAccessibleSecretFromAnyVault("SEC", "FP2"); err == nil {
		t.Errorf("FP2 got %q from before the deletion; want no accessible value", val.Value)
	}

	m := r.GetVaultManager(0)
	if m.CanIdentityAccessSecret("FP2", "SEC") {
		t.Error("FP2 counts as having access through a deleted value")
	}
	if !m.CanIdentityAccessSecret("FP1", "SEC") {
		t.Error("FP1 should have access to the live value")
	}

	compacted, stats := PlanCompaction(m.Get())
	if len(compacted.Secrets) != 1 {
		t.Fatalf("expected the re-stored secret kept, got %d secrets", len(compacted.Secrets))
	}
	kept := compacted.Secrets[0].Values
	if len(kept) != 1 || kept[0].Value != "v2" {
		t.Errorf("compaction kept %+v, want only v2", kept)
	}
	if st := secretStat(t, stats, "SEC"); st.Before != 3 || st.After != 1 || st.Removed {
		t.Errorf("stat = %+v, want before 3 after 1, not removed", st)
	}
}

// A deletion in one vault does not hide the secret held by a later vault.
func TestDeletedInFirstVault_FallsThroughToNext(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	appendHistory(t, first, "SEC", history(
		SecretValue{AvailableTo: []string{"FP1"}, Value: "gone"},
		tombstone(),
	)...)
	appendHistory(t, second, "SEC", history(
		SecretValue{AvailableTo: []string{"FP1"}, Value: "kept"},
	)...)

	r := openResolver(t, first, second)

	if val, idx, err := r.GetAccessibleSecretFromAnyVault("SEC", "FP1"); err != nil || val.Value != "kept" || idx != 1 {
		t.Errorf("accessible lookup = (%v, %d, %v), want kept from vault 1", val, idx, err)
	}
	if val, idx, err := r.GetSecretFromAnyVault("SEC", nil); err != nil || val.Value != "kept" || idx != 1 {
		t.Errorf("latest-value lookup = (%v, %d, %v), want kept from vault 1", val, idx, err)
	}
	if idx := r.FindSecretVaultIndex("SEC"); idx != 1 {
		t.Errorf("FindSecretVaultIndex = %d, want 1", idx)
	}
	keys := r.ListAllSecretKeys()
	if len(keys) != 1 || keys[0].Deleted || keys[0].VaultIdx != 2 {
		t.Errorf("ListAllSecretKeys = %+v, want SEC live in vault 2", keys)
	}
}

func TestDeletedInEveryVault(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	for _, p := range []string{first, second} {
		appendHistory(t, p, "SEC", history(
			SecretValue{AvailableTo: []string{"FP1"}, Value: "gone"},
			tombstone(),
		)...)
	}

	r := openResolver(t, first, second)

	if _, _, err := r.GetSecretFromAnyVault("SEC", nil); err == nil {
		t.Error("expected no value for a secret deleted in every vault")
	}
	if idx := r.FindSecretVaultIndex("SEC"); idx != 0 {
		t.Errorf("FindSecretVaultIndex = %d, want 0 (first vault holding it)", idx)
	}
	keys := r.ListAllSecretKeys()
	if len(keys) != 1 || !keys[0].Deleted || keys[0].VaultIdx != 1 {
		t.Errorf("ListAllSecretKeys = %+v, want SEC deleted in vault 1", keys)
	}
}
