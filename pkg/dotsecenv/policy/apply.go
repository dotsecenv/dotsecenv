package policy

import (
	"fmt"
	"sort"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
)

// Apply intersects the user's config with the policy's effective allow-lists
// and overrides the user's scalar fields with policy's effective scalars.
// Returns the constrained Config plus warnings describing what changed.
// Returns cfg unchanged when p is empty (no policy enforced).
//
// Allow-list semantics (intersection): user's `approved_algorithms` is
// narrowed by policy; user's `vault` list is filtered by `approved_vault_paths`.
//
// Scalar semantics (policy overrides user): if policy sets `gpg.program` or
// any `behavior.*` field, that value replaces the user's. Same value across
// user and policy is silently honored (no warning); different value emits a
// "policy overrides user X" warning so users know their config was overridden.
//
// Cross-fragment scalar conflicts (later fragment changes a value set by an
// earlier one) are surfaced separately as `policy conflict` warnings —
// independent of whether the policy overrides any user value.
func Apply(cfg config.Config, p Policy) (config.Config, []string) {
	if p.Empty() {
		return cfg, nil
	}

	var warnings []string

	polAlgos, _ := p.MergedApprovedAlgorithms()
	if len(polAlgos) > 0 {
		intersected, w := intersectApprovedAlgorithms(cfg.ApprovedAlgorithms, polAlgos)
		cfg.ApprovedAlgorithms = intersected
		warnings = append(warnings, w...)
	}

	polVaultPatterns, _ := p.MergedApprovedVaultPaths()
	if len(polVaultPatterns) > 0 {
		filtered, w := filterApprovedVaults(cfg.Vault, p)
		cfg.Vault = filtered
		warnings = append(warnings, w...)
	}

	// Scalar overrides (policy wins over user). Cross-fragment conflict
	// warnings come from MergedBehavior/MergedGPGProgram; user-override
	// warnings come from the merging step below.
	polBehavior, behaviorOrigins, behaviorConflicts := p.MergedBehavior()
	warnings = append(warnings, behaviorConflicts...)
	cfg.Behavior, warnings = applyBehaviorOverride(cfg.Behavior, polBehavior, behaviorOrigins, warnings)

	polGPGProgram, polGPGOrigin, gpgConflicts := p.MergedGPGProgram()
	warnings = append(warnings, gpgConflicts...)
	if polGPGProgram != "" {
		if cfg.GPG.Program != "" && cfg.GPG.Program != polGPGProgram {
			warnings = append(warnings, fmt.Sprintf(
				"policy overrides user gpg.program: user value %q replaced by %q from %s",
				cfg.GPG.Program, polGPGProgram, polGPGOrigin,
			))
		}
		cfg.GPG.Program = polGPGProgram
	}

	return cfg, warnings
}

// applyBehaviorOverride applies each policy-set behavior.* sub-field to cfg.
// When the user previously had a different value, appends a
// "policy overrides user behavior.X" warning so the silent change is visible.
// Returns the updated BehaviorConfig and warnings slice.
func applyBehaviorOverride(user, pol config.BehaviorConfig, polOrigins map[string]string, warnings []string) (config.BehaviorConfig, []string) {
	for _, fld := range behaviorFields {
		polVal := fld.get(pol)
		if polVal == nil {
			continue // policy doesn't constrain this field
		}
		userVal := fld.get(user)
		if userVal != nil && *userVal != *polVal {
			warnings = append(warnings, fmt.Sprintf(
				"policy overrides user %s: user value %v replaced by %v from %s",
				fld.name, *userVal, *polVal, polOrigins[fld.name],
			))
		}
		fld.set(&user, polVal)
	}
	return user, warnings
}

// intersectApprovedAlgorithms narrows the user's allow-list to entries also
// permitted by policy. Same-algo entries: take user_curves ∩ policy_curves
// and max(user_min_bits, policy_min_bits) — the stricter of the two governs.
// User entries with no matching policy entry are dropped with a warning.
func intersectApprovedAlgorithms(user, policy []config.ApprovedAlgorithm) ([]config.ApprovedAlgorithm, []string) {
	polByAlgo := map[string]config.ApprovedAlgorithm{}
	for _, a := range policy {
		polByAlgo[a.Algo] = a
	}

	var (
		out      []config.ApprovedAlgorithm
		warnings []string
	)

	for _, u := range user {
		pol, ok := polByAlgo[u.Algo]
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"policy excludes %s from your approved_algorithms",
				u.Algo,
			))
			continue
		}

		merged := config.ApprovedAlgorithm{
			Algo:    u.Algo,
			MinBits: maxInt(u.MinBits, pol.MinBits),
		}

		// Curves: intersection. Empty on either side means "all curves in the
		// family", so the other side governs.
		switch {
		case len(u.Curves) == 0 && len(pol.Curves) == 0:
			// both unconstrained; merged.Curves stays nil
		case len(u.Curves) == 0:
			merged.Curves = append([]string{}, pol.Curves...)
		case len(pol.Curves) == 0:
			merged.Curves = append([]string{}, u.Curves...)
		default:
			polSet := map[string]struct{}{}
			for _, c := range pol.Curves {
				polSet[c] = struct{}{}
			}
			for _, c := range u.Curves {
				if _, ok := polSet[c]; ok {
					merged.Curves = append(merged.Curves, c)
				}
			}
			if len(merged.Curves) == 0 {
				warnings = append(warnings, fmt.Sprintf(
					"policy and your approved_algorithms have no common curves for %s; this algorithm is now unusable",
					u.Algo,
				))
				continue
			}
			sort.Strings(merged.Curves)
		}

		if u.MinBits != merged.MinBits {
			warnings = append(warnings, fmt.Sprintf(
				"policy raises min_bits for %s from %d to %d",
				u.Algo, u.MinBits, merged.MinBits,
			))
		}

		out = append(out, merged)
	}

	return out, warnings
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// filterApprovedVaults retains only the user vault paths that match at least
// one of the policy's approved_vault_paths patterns. Dropped paths produce
// warnings explaining the policy attribution.
func filterApprovedVaults(userVaults []string, p Policy) ([]string, []string) {
	var (
		out      []string
		warnings []string
	)
	for _, v := range userVaults {
		if p.IsVaultPathAllowed(v) {
			out = append(out, v)
			continue
		}
		patterns, _ := p.MergedApprovedVaultPaths()
		warnings = append(warnings, fmt.Sprintf(
			"policy filters vault path %s (not matched by approved_vault_paths: %v)",
			v, patterns,
		))
	}
	return out, warnings
}
