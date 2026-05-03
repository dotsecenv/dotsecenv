package policy

import (
	"sort"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
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
