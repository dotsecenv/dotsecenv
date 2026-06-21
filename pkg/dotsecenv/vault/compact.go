package vault

import (
	"fmt"
	"slices"
)

// CompactSecretStat describes the compaction effect on a single secret.
type CompactSecretStat struct {
	// Key is the secret name.
	Key string
	// Before is the value count before compaction.
	Before int
	// After is the value count after compaction (0 if removed).
	After int
	// Removed is true when the whole secret was dropped because it was deleted.
	Removed bool
}

// CompactStats summarizes a compaction.
type CompactStats struct {
	// Secrets holds the per-secret effect, in vault order.
	Secrets []CompactSecretStat
	// ValuesBefore is the total value count across all secrets before compaction.
	ValuesBefore int
	// ValuesAfter is the total value count across kept secrets after compaction.
	ValuesAfter int
	// ValuesDropped is ValuesBefore minus ValuesAfter.
	ValuesDropped int
	// SecretsRemoved is the number of deleted secrets dropped entirely.
	SecretsRemoved int
}

// Changed reports whether compaction would alter the vault.
func (s *CompactStats) Changed() bool {
	return s.ValuesDropped > 0 || s.SecretsRemoved > 0
}

// PlanCompaction computes the compacted vault and statistics without writing.
//
// Compaction drops superseded secret-value versions. For each secret it keeps,
// per current identity, the newest value that identity can decrypt — which is
// exactly what `secret get` would return for that identity. Values no current
// identity reaches (including versions readable only by revoked fingerprints)
// are dropped. Deleted secrets (latest value is a tombstone) are removed
// entirely. Identities are never touched.
//
// Compaction never decrypts: it reads only available_to fingerprints and value
// order, and it preserves each kept value verbatim (added_at, available_to,
// signed_by, value, hash, signature), so signatures stay valid after the rewrite.
func PlanCompaction(v Vault) (Vault, *CompactStats) {
	current := make(map[string]bool, len(v.Identities))
	for _, id := range v.Identities {
		current[id.Fingerprint] = true
	}

	stats := &CompactStats{}
	compacted := Vault{Identities: v.Identities}

	for i := range v.Secrets {
		s := v.Secrets[i]
		before := len(s.Values)
		stats.ValuesBefore += before

		// A deleted secret is unreachable via `get` regardless of recipients;
		// drop the whole record (definition + every value, including the tombstone).
		if s.IsDeleted() {
			stats.Secrets = append(stats.Secrets, CompactSecretStat{
				Key: s.Key, Before: before, After: 0, Removed: true,
			})
			stats.SecretsRemoved++
			stats.ValuesDropped += before
			continue
		}

		keep := make([]bool, len(s.Values))
		for fp := range current {
			// Newest value this identity can decrypt (scan newest -> oldest).
			for j := len(s.Values) - 1; j >= 0; j-- {
				if s.Values[j].Deleted {
					continue
				}
				if slices.Contains(s.Values[j].AvailableTo, fp) {
					keep[j] = true
					break
				}
			}
		}

		kept := make([]SecretValue, 0, len(s.Values))
		for j := range s.Values {
			if keep[j] {
				kept = append(kept, s.Values[j])
			}
		}
		// Floor: if no current identity can read any version (e.g. the secret is
		// shared only with revoked fingerprints), keep the latest value so the
		// secret still exists and is not silently emptied. Its decryptability is
		// unchanged — nobody current could read it before either.
		if len(kept) == 0 && len(s.Values) > 0 {
			kept = append(kept, s.Values[len(s.Values)-1])
		}

		s.Values = kept
		after := len(kept)
		stats.ValuesAfter += after
		stats.ValuesDropped += before - after
		stats.Secrets = append(stats.Secrets, CompactSecretStat{
			Key: s.Key, Before: before, After: after,
		})
		compacted.Secrets = append(compacted.Secrets, s)
	}

	return compacted, stats
}

// Compact reads the vault, drops superseded value versions and deleted secrets,
// and rewrites the file. It returns the compaction statistics. When nothing
// would change, the file is left untouched.
func Compact(w *Writer) (*CompactStats, error) {
	v, err := w.ReadVault()
	if err != nil {
		return nil, fmt.Errorf("failed to read vault for compaction: %w", err)
	}

	compacted, stats := PlanCompaction(v)
	if !stats.Changed() {
		return stats, nil
	}

	if err := w.RewriteFromVault(compacted); err != nil {
		return nil, fmt.Errorf("failed to rewrite vault: %w", err)
	}

	return stats, nil
}
