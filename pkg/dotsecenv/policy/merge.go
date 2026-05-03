package policy

import (
	"path/filepath"
	"sort"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// MergedApprovedAlgorithms returns the cross-fragment union of approved_algorithms
// with most-permissive reconciliation: same-algo entries collapse, curves union,
// min_bits takes the minimum across all fragments.
//
// origins[i] contains the fragment paths that contributed to entries[i], in
// load order. Used by `dotsecenv policy list` for per-field attribution.
func (p Policy) MergedApprovedAlgorithms() (entries []config.ApprovedAlgorithm, origins [][]string) {
	type bucket struct {
		algo    string
		curves  map[string]struct{}
		minBits int
		origins []string
		seen    map[string]struct{} // dedupe origins
	}
	byAlgo := map[string]*bucket{}
	var algoOrder []string

	for _, f := range p.Fragments {
		for _, a := range f.ApprovedAlgorithms {
			b, ok := byAlgo[a.Algo]
			if !ok {
				b = &bucket{
					algo:    a.Algo,
					curves:  map[string]struct{}{},
					minBits: a.MinBits,
					seen:    map[string]struct{}{},
				}
				byAlgo[a.Algo] = b
				algoOrder = append(algoOrder, a.Algo)
			}
			for _, c := range a.Curves {
				b.curves[c] = struct{}{}
			}
			if a.MinBits < b.minBits {
				b.minBits = a.MinBits
			}
			if _, dup := b.seen[f.Path]; !dup {
				b.origins = append(b.origins, f.Path)
				b.seen[f.Path] = struct{}{}
			}
		}
	}

	for _, algo := range algoOrder {
		b := byAlgo[algo]
		var curves []string
		for c := range b.curves {
			curves = append(curves, c)
		}
		sort.Strings(curves)
		entries = append(entries, config.ApprovedAlgorithm{
			Algo:    b.algo,
			Curves:  curves,
			MinBits: b.minBits,
		})
		origins = append(origins, b.origins)
	}
	return entries, origins
}

// MergedApprovedVaultPaths returns the deduped cross-fragment union of
// approved_vault_paths patterns plus an origin map (pattern -> fragment paths
// that contributed it). Patterns are returned in first-seen order across
// fragments (lexical fragment order, then within-fragment order).
func (p Policy) MergedApprovedVaultPaths() (patterns []string, origins map[string][]string) {
	origins = map[string][]string{}
	seen := map[string]struct{}{}
	for _, f := range p.Fragments {
		for _, pat := range f.ApprovedVaultPaths {
			if _, ok := seen[pat]; !ok {
				patterns = append(patterns, pat)
				seen[pat] = struct{}{}
			}
			// Append origin if this fragment hasn't already been recorded for this pattern.
			origs := origins[pat]
			if len(origs) == 0 || origs[len(origs)-1] != f.Path {
				origins[pat] = append(origs, f.Path)
			}
		}
	}
	return patterns, origins
}

// IsVaultPathAllowed reports whether vaultPath matches any of the policy's
// approved_vault_paths patterns. When the policy has no approved_vault_paths
// set (e.g. an empty or absent policy), this returns true — the policy
// doesn't constrain vault paths in that case.
//
// Matching uses filepath.Match (single-segment wildcards: *, ?, [abc]) with
// `~` expansion via vault.ExpandPath on both pattern and path before matching.
// Both are also passed through filepath.Abs (best-effort) to normalize.
func (p Policy) IsVaultPathAllowed(vaultPath string) bool {
	patterns, _ := p.MergedApprovedVaultPaths()
	if len(patterns) == 0 {
		return true
	}
	target := normalizePath(vaultPath)
	for _, pat := range patterns {
		if matched, _ := filepath.Match(normalizePath(pat), target); matched {
			return true
		}
	}
	return false
}

// normalizePath expands ~ and resolves to absolute (best-effort).
// Used to give pattern and target a common representation before
// filepath.Match. Returns the original input on resolution failure.
func normalizePath(p string) string {
	expanded := vault.ExpandPath(p)
	if abs, err := filepath.Abs(expanded); err == nil {
		return abs
	}
	return expanded
}
