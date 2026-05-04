package policy

import (
	"fmt"
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

// MergedGPGProgram returns the cross-fragment merged gpg.program scalar.
// Last-fragment-to-set wins (lexical filename order; matches sudoers.d/systemd
// drop-in convention). Empty string in a fragment = "not set". Returns the
// merged value, the origin path of the winning fragment (or "" if no fragment
// set it), and conflict warnings — one per chained override where a later
// fragment changed the value to something different from the previous setter.
//
// Same value across fragments emits no warning (it's redundant, not a
// conflict). Different values emit "policy conflict on gpg.program: …".
func (p Policy) MergedGPGProgram() (program string, origin string, conflicts []string) {
	for _, f := range p.Fragments {
		if f.GPG.Program == "" {
			continue
		}
		if origin != "" && f.GPG.Program != program {
			conflicts = append(conflicts, fmt.Sprintf(
				"policy conflict on gpg.program: overridden to %q by %s; previous value %q from %s",
				f.GPG.Program, f.Path, program, origin,
			))
		}
		program = f.GPG.Program
		origin = f.Path
	}
	return program, origin, conflicts
}

// behaviorField is one settable sub-field of config.BehaviorConfig. The
// closure-based accessor pattern keeps MergedBehavior independent of how
// many sub-fields the BehaviorConfig type has — adding a new behavior
// field is a one-line append here, no merge-engine changes.
type behaviorField struct {
	name string
	get  func(config.BehaviorConfig) *bool
	set  func(*config.BehaviorConfig, *bool)
}

var behaviorFields = []behaviorField{
	{
		name: "behavior.require_explicit_vault_upgrade",
		get:  func(b config.BehaviorConfig) *bool { return b.RequireExplicitVaultUpgrade },
		set:  func(b *config.BehaviorConfig, v *bool) { b.RequireExplicitVaultUpgrade = v },
	},
	{
		name: "behavior.restrict_to_configured_vaults",
		get:  func(b config.BehaviorConfig) *bool { return b.RestrictToConfiguredVaults },
		set:  func(b *config.BehaviorConfig, v *bool) { b.RestrictToConfiguredVaults = v },
	},
}

// MergedBehavior returns the cross-fragment merged behavior.* fields.
// Each sub-field independently uses last-fragment-to-set wins; nil = not set.
// Returns the merged BehaviorConfig, per-field-name origin (which fragment
// set the final value), and conflict warnings — one per chained override
// per sub-field where a later fragment changed the value.
//
// Sub-fields are independent: behavior.A set by fragment 1 and behavior.B
// set by fragment 2 produces no conflicts (they touch different fields).
func (p Policy) MergedBehavior() (b config.BehaviorConfig, origins map[string]string, conflicts []string) {
	origins = map[string]string{}

	for _, fld := range behaviorFields {
		var (
			currentValue  *bool
			currentOrigin string
		)
		for _, frag := range p.Fragments {
			v := fld.get(frag.Behavior)
			if v == nil {
				continue
			}
			if currentValue != nil && *v != *currentValue {
				conflicts = append(conflicts, fmt.Sprintf(
					"policy conflict on %s: overridden to %v by %s; previous value %v from %s",
					fld.name, *v, frag.Path, *currentValue, currentOrigin,
				))
			}
			currentValue = v
			currentOrigin = frag.Path
		}
		if currentValue != nil {
			fld.set(&b, currentValue)
			origins[fld.name] = currentOrigin
		}
	}
	return b, origins, conflicts
}
