package vault

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// secretStat looks up the per-secret stat by key.
func secretStat(t *testing.T, stats *CompactStats, key string) CompactSecretStat {
	t.Helper()
	for _, s := range stats.Secrets {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("no stat for secret %q", key)
	return CompactSecretStat{}
}

func TestPlanCompaction_KeepsNewestPerIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := Vault{
		Identities: []identity.Identity{
			{Fingerprint: "FP1"},
			{Fingerprint: "FP2"},
		},
		Secrets: []Secret{{
			Key: "SEC",
			Values: []SecretValue{
				{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
				{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1", "FP2"}, Value: "v2"},
				{AddedAt: now.Add(2 * time.Second), AvailableTo: []string{"FP1", "FP2"}, Value: "v3"},
			},
		}},
	}

	compacted, stats := PlanCompaction(v)

	if got := len(compacted.Secrets[0].Values); got != 1 {
		t.Fatalf("expected 1 kept value, got %d", got)
	}
	if compacted.Secrets[0].Values[0].Value != "v3" {
		t.Errorf("expected newest value v3 kept, got %q", compacted.Secrets[0].Values[0].Value)
	}
	st := secretStat(t, stats, "SEC")
	if st.Before != 3 || st.After != 1 {
		t.Errorf("stat = %+v, want before 3 after 1", st)
	}
	if !stats.Changed() || stats.ValuesDropped != 2 {
		t.Errorf("expected 2 dropped, stats=%+v", stats)
	}
}

func TestPlanCompaction_KeepsDistinctRecipientNewest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := Vault{
		Identities: []identity.Identity{
			{Fingerprint: "FP1"},
			{Fingerprint: "FP2"},
		},
		Secrets: []Secret{{
			Key: "SEC",
			Values: []SecretValue{
				{AddedAt: now, AvailableTo: []string{"FP1", "FP2"}, Value: "v1"},
				{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1"}, Value: "v2"},
			},
		}},
	}

	compacted, _ := PlanCompaction(v)

	// FP1's newest is v2; FP2's newest is v1 -> both kept, recency order preserved.
	got := compacted.Secrets[0].Values
	if len(got) != 2 {
		t.Fatalf("expected 2 kept values, got %d", len(got))
	}
	if got[0].Value != "v1" || got[1].Value != "v2" {
		t.Errorf("expected order [v1 v2], got [%s %s]", got[0].Value, got[1].Value)
	}
}

func TestPlanCompaction_DropsRevokedOnlyValues(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := Vault{
		Identities: []identity.Identity{{Fingerprint: "FP1"}}, // FP2 is revoked (absent)
		Secrets: []Secret{{
			Key: "SEC",
			Values: []SecretValue{
				{AddedAt: now, AvailableTo: []string{"FP1", "FP2"}, Value: "v1"},
				{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP2"}, Value: "v2"},
			},
		}},
	}

	compacted, _ := PlanCompaction(v)

	got := compacted.Secrets[0].Values
	if len(got) != 1 || got[0].Value != "v1" {
		t.Fatalf("expected only v1 kept (newest FP1 can read), got %+v", got)
	}
}

func TestPlanCompaction_RemovesDeletedSecret(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := Vault{
		Identities: []identity.Identity{{Fingerprint: "FP1"}},
		Secrets: []Secret{
			{
				Key: "GONE",
				Values: []SecretValue{
					{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"},
					{AddedAt: now.Add(time.Second), AvailableTo: []string{}, Deleted: true},
				},
			},
			{
				Key:    "LIVE",
				Values: []SecretValue{{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "x"}},
			},
		},
	}

	compacted, stats := PlanCompaction(v)

	if len(compacted.Secrets) != 1 || compacted.Secrets[0].Key != "LIVE" {
		t.Fatalf("expected only LIVE to remain, got %+v", compacted.Secrets)
	}
	if stats.SecretsRemoved != 1 {
		t.Errorf("expected 1 secret removed, got %d", stats.SecretsRemoved)
	}
	if st := secretStat(t, stats, "GONE"); !st.Removed || st.After != 0 {
		t.Errorf("GONE stat = %+v, want removed", st)
	}
}

func TestPlanCompaction_FloorKeepsLatestWhenNobodyCurrentReads(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := Vault{
		Identities: []identity.Identity{{Fingerprint: "FP1"}},
		Secrets: []Secret{{
			Key: "ORPHAN",
			Values: []SecretValue{
				{AddedAt: now, AvailableTo: []string{"FP2"}, Value: "v1"},
				{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP2"}, Value: "v2"},
			},
		}},
	}

	compacted, _ := PlanCompaction(v)

	got := compacted.Secrets[0].Values
	if len(got) != 1 || got[0].Value != "v2" {
		t.Fatalf("expected latest value v2 kept as floor, got %+v", got)
	}
}

func TestPlanCompaction_NoOpWhenAlreadyMinimal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	v := Vault{
		Identities: []identity.Identity{{Fingerprint: "FP1"}},
		Secrets: []Secret{{
			Key:    "SEC",
			Values: []SecretValue{{AddedAt: now, AvailableTo: []string{"FP1"}, Value: "v1"}},
		}},
	}

	_, stats := PlanCompaction(v)
	if stats.Changed() {
		t.Errorf("expected no change, stats=%+v", stats)
	}
}

// TestCompact_RoundTripPreservesValues runs compaction through the writer and
// confirms kept values are byte-for-byte preserved (signature fields intact)
// and the file is re-readable.
func TestCompact_RoundTripPreservesValues(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	seed := Vault{
		Identities: []identity.Identity{
			{AddedAt: now, Fingerprint: "FP1"},
			{AddedAt: now, Fingerprint: "FP2"},
		},
		Secrets: []Secret{{
			AddedAt:   now,
			Key:       "SEC",
			Hash:      "secret-hash",
			Signature: "secret-sig",
			SignedBy:  "FP1",
			Values: []SecretValue{
				{AddedAt: now, AvailableTo: []string{"FP1", "FP2"}, Value: "old", Hash: "h1", Signature: "s1", SignedBy: "FP1"},
				{AddedAt: now.Add(time.Second), AvailableTo: []string{"FP1", "FP2"}, Value: "new", Hash: "h2", Signature: "s2", SignedBy: "FP1"},
			},
		}},
	}
	if err := w.RewriteFromVault(seed); err != nil {
		t.Fatalf("seed RewriteFromVault failed: %v", err)
	}

	stats, err := Compact(w)
	if err != nil {
		t.Fatalf("Compact failed: %v", err)
	}
	if stats.ValuesDropped != 1 {
		t.Errorf("expected 1 value dropped, got %d", stats.ValuesDropped)
	}

	// Re-open from disk to confirm the rewrite persisted and is re-readable.
	w2, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("re-open NewWriter failed: %v", err)
	}
	got, err := w2.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	if len(got.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(got.Identities))
	}
	if len(got.Secrets) != 1 || len(got.Secrets[0].Values) != 1 {
		t.Fatalf("expected 1 secret with 1 value, got %+v", got.Secrets)
	}
	kept := got.Secrets[0].Values[0]
	if kept.Value != "new" || kept.Hash != "h2" || kept.Signature != "s2" || kept.SignedBy != "FP1" {
		t.Errorf("kept value not preserved verbatim: %+v", kept)
	}
}
