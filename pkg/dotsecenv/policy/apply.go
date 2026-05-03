package policy

import (
	"fmt"
	"sort"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
)

// Apply intersects the user's config with the policy's effective allow-lists
// and returns the constrained Config plus warnings describing what changed.
// Returns cfg unchanged when p is empty (no policy enforced).
//
// PR #3 will add scalar overrides (behavior.*, gpg.program).
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

	return cfg, warnings
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
