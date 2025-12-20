package vault

import (
	"fmt"
	"math"
	"sort"
)

// Defragmentation thresholds
const (
	// SmallVaultThreshold is the entry count below which defragmentation is never needed
	SmallVaultThreshold = 500

	// MediumVaultThreshold is the entry count above which stricter fragmentation rules apply
	MediumVaultThreshold = 2000

	// SmallVaultFragmentationThreshold is the fragmentation ratio above which
	// a medium-sized vault should be defragmented (40%)
	SmallVaultFragmentationThreshold = 0.40

	// LargeVaultFragmentationThreshold is the fragmentation ratio above which
	// a large vault should be defragmented (30%)
	LargeVaultFragmentationThreshold = 0.30
)

// FragmentationStats contains detailed fragmentation metrics
type FragmentationStats struct {
	// TotalEntries is the total number of data entries
	TotalEntries int

	// TotalLines is the total number of lines in the file (including header)
	TotalLines int

	// HeaderLines is the number of header/comment lines
	HeaderLines int

	// FragmentationRatio is the overall fragmentation (0.0 = perfect, 1.0 = completely fragmented)
	FragmentationRatio float64

	// AverageSecretSpread is the average distance between a secret definition and its values
	AverageSecretSpread float64

	// MaxSecretSpread is the maximum spread for any single secret
	MaxSecretSpread int

	// SecretsWithSpread is the number of secrets whose values are not consecutive
	SecretsWithSpread int

	// RecommendDefrag indicates whether defragmentation is recommended
	RecommendDefrag bool

	// Reason explains why defragmentation is or isn't recommended
	Reason string
}

// CalculateFragmentation analyzes the vault and returns fragmentation statistics
func CalculateFragmentation(r *Reader) (*FragmentationStats, error) {
	header := r.Header()

	stats := &FragmentationStats{
		HeaderLines: 3, // header marker, header JSON, data marker
	}

	// Count entries
	stats.TotalEntries = len(header.Identities)
	for _, idx := range header.Secrets {
		stats.TotalEntries++ // secret definition
		stats.TotalEntries += len(idx.Values)
	}

	stats.TotalLines = r.TotalLines()

	// Calculate fragmentation metrics for secrets
	var totalSpread float64
	spreadsCount := 0

	for _, idx := range header.Secrets {
		if len(idx.Values) == 0 {
			continue
		}

		// Calculate spread: distance from secret definition to its values
		// and between consecutive values
		allLines := append([]int{idx.Definition}, idx.Values...)
		sort.Ints(allLines)

		// Ideal: all entries consecutive (spread = len(allLines) - 1)
		// Actual: last - first
		idealSpread := len(allLines) - 1
		actualSpread := allLines[len(allLines)-1] - allLines[0]

		if actualSpread > idealSpread {
			spread := actualSpread - idealSpread
			totalSpread += float64(spread)
			spreadsCount++
			stats.SecretsWithSpread++

			if spread > stats.MaxSecretSpread {
				stats.MaxSecretSpread = spread
			}
		}
	}

	if spreadsCount > 0 {
		stats.AverageSecretSpread = totalSpread / float64(spreadsCount)
	}

	// Calculate overall fragmentation ratio
	// Ideal file: entries = lines - header lines
	// Fragmentation = (actual lines - ideal lines) / actual lines
	idealDataLines := stats.TotalEntries
	actualDataLines := stats.TotalLines - stats.HeaderLines

	if actualDataLines > 0 && actualDataLines > idealDataLines {
		// There are "wasted" lines (this shouldn't happen in append-only mode
		// but can happen after future features like deletion)
		stats.FragmentationRatio = float64(actualDataLines-idealDataLines) / float64(actualDataLines)
	}

	// Also factor in value spread as a fragmentation metric
	if stats.TotalEntries > 0 && stats.AverageSecretSpread > 0 {
		// Normalize spread: spread of N means N extra seeks needed
		// Compare to total entries to get impact
		spreadImpact := stats.AverageSecretSpread / float64(stats.TotalEntries)
		if spreadImpact > stats.FragmentationRatio {
			stats.FragmentationRatio = math.Min(spreadImpact, 1.0)
		}
	}

	// Determine if defragmentation is recommended
	stats.RecommendDefrag, stats.Reason = shouldDefragment(stats)

	return stats, nil
}

// shouldDefragment determines if defragmentation is recommended
func shouldDefragment(stats *FragmentationStats) (bool, string) {
	// Small vaults: never need defragmentation
	if stats.TotalEntries < SmallVaultThreshold {
		return false, fmt.Sprintf(
			"vault has %d entries (< %d threshold), defragmentation not needed",
			stats.TotalEntries, SmallVaultThreshold)
	}

	// Medium vaults: defrag if fragmentation > 40%
	if stats.TotalEntries < MediumVaultThreshold {
		if stats.FragmentationRatio > SmallVaultFragmentationThreshold {
			return true, fmt.Sprintf(
				"vault has %d entries with %.1f%% fragmentation (> %.0f%% threshold)",
				stats.TotalEntries, stats.FragmentationRatio*100, SmallVaultFragmentationThreshold*100)
		}
		return false, fmt.Sprintf(
			"vault has %d entries with %.1f%% fragmentation (< %.0f%% threshold)",
			stats.TotalEntries, stats.FragmentationRatio*100, SmallVaultFragmentationThreshold*100)
	}

	// Large vaults: defrag if fragmentation > 30%
	if stats.FragmentationRatio > LargeVaultFragmentationThreshold {
		return true, fmt.Sprintf(
			"large vault has %d entries with %.1f%% fragmentation (> %.0f%% threshold)",
			stats.TotalEntries, stats.FragmentationRatio*100, LargeVaultFragmentationThreshold*100)
	}

	return false, fmt.Sprintf(
		"large vault has %d entries with %.1f%% fragmentation (< %.0f%% threshold)",
		stats.TotalEntries, stats.FragmentationRatio*100, LargeVaultFragmentationThreshold*100)
}

// Defragment rewrites the vault file with all entries in optimal order:
// - All identities first (sorted by AddedAt)
// - Each secret followed immediately by its values (secrets sorted by key, values by AddedAt)
func Defragment(w *Writer) (*FragmentationStats, error) {
	// Read current vault state
	vault, err := w.ReadVault()
	if err != nil {
		return nil, fmt.Errorf("failed to read vault for defragmentation: %w", err)
	}

	// Sort identities by AddedAt
	sort.Slice(vault.Identities, func(i, j int) bool {
		return vault.Identities[i].AddedAt.Before(vault.Identities[j].AddedAt)
	})

	// Sort secrets by key
	sort.Slice(vault.Secrets, func(i, j int) bool {
		return vault.Secrets[i].Key < vault.Secrets[j].Key
	})

	// Sort values within each secret by AddedAt
	for i := range vault.Secrets {
		sort.Slice(vault.Secrets[i].Values, func(a, b int) bool {
			return vault.Secrets[i].Values[a].AddedAt.Before(vault.Secrets[i].Values[b].AddedAt)
		})
		// Sort available_to fingerprints alphabetically
		for j := range vault.Secrets[i].Values {
			sort.Strings(vault.Secrets[i].Values[j].AvailableTo)
		}
	}

	// Rewrite the vault
	if err := w.RewriteFromVault(vault); err != nil {
		return nil, fmt.Errorf("failed to rewrite vault: %w", err)
	}

	// Calculate new stats
	reader, err := NewReader(w.Path())
	if err != nil {
		return nil, fmt.Errorf("failed to create reader for stats: %w", err)
	}

	return CalculateFragmentation(reader)
}

// DefragmentIfNeeded checks fragmentation and defragments only if recommended
func DefragmentIfNeeded(w *Writer) (*FragmentationStats, bool, error) {
	reader, err := NewReader(w.Path())
	if err != nil {
		return nil, false, fmt.Errorf("failed to create reader: %w", err)
	}

	stats, err := CalculateFragmentation(reader)
	if err != nil {
		return nil, false, fmt.Errorf("failed to calculate fragmentation: %w", err)
	}

	if !stats.RecommendDefrag {
		return stats, false, nil
	}

	newStats, err := Defragment(w)
	if err != nil {
		return stats, false, fmt.Errorf("defragmentation failed: %w", err)
	}

	return newStats, true, nil
}

// OptimalOrderEstimate calculates what the line count would be after defragmentation
func OptimalOrderEstimate(header *Header) int {
	// 3 header lines + all entries consecutive
	entries := len(header.Identities)
	for _, idx := range header.Secrets {
		entries++ // secret definition
		entries += len(idx.Values)
	}
	return 3 + entries
}
