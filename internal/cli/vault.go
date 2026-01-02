package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// VaultListSecretJSON represents a secret in the vault list JSON output
type VaultListSecretJSON struct {
	Key     string `json:"key"`
	Deleted bool   `json:"deleted,omitempty"`
}

// VaultListJSON is the JSON output structure for vault list
type VaultListJSON struct {
	Position int                   `json:"position"`
	Vault    string                `json:"vault"`
	Secrets  []VaultListSecretJSON `json:"secrets"`
}

// VaultList lists all vaults and their keys
func (c *CLI) VaultList(jsonOutput bool) *Error {
	config := c.vaultResolver.GetConfig()

	if jsonOutput {
		var output []VaultListJSON
		for i, entry := range config.Entries {
			manager := c.vaultResolver.GetVaultManager(i)

			// Ensure paths match (manager path is absolute)
			if manager != nil {
				entryAbs, _ := filepath.Abs(entry.Path)
				managerAbs, _ := filepath.Abs(manager.Path())
				if entryAbs != managerAbs {
					manager = nil // Mismatch
				}
			}

			if manager != nil {
				vaultData := manager.Get()
				var secrets []VaultListSecretJSON
				for _, s := range vaultData.Secrets {
					secrets = append(secrets, VaultListSecretJSON{
						Key:     s.Key,
						Deleted: s.IsDeleted(),
					})
				}
				sort.Slice(secrets, func(i, j int) bool {
					return secrets[i].Key < secrets[j].Key
				})

				output = append(output, VaultListJSON{
					Position: i + 1,
					Vault:    entry.Path,
					Secrets:  secrets,
				})
			}
		}

		encoder := json.NewEncoder(c.output.Stdout())
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(output); err != nil {
			return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
		}
		return nil
	}

	// Text output
	for i, entry := range config.Entries {
		if i > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "\n")
		}
		displayPos := i + 1
		manager := c.vaultResolver.GetVaultManager(i)

		// Verify manager path
		if manager != nil {
			entryAbs, _ := filepath.Abs(entry.Path)
			managerAbs, _ := filepath.Abs(manager.Path())
			if entryAbs != managerAbs {
				manager = nil
			}
		}

		if manager == nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): Failed to load\n", displayPos, entry.Path)
		} else {
			vaultData := manager.Get()
			if len(vaultData.Secrets) == 0 {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s):\n  (no secrets)\n", displayPos, entry.Path)
			} else {
				type secretInfo struct {
					key     string
					deleted bool
				}
				var secrets []secretInfo
				for _, s := range vaultData.Secrets {
					secrets = append(secrets, secretInfo{
						key:     s.Key,
						deleted: s.IsDeleted(),
					})
				}
				sort.Slice(secrets, func(i, j int) bool {
					return secrets[i].key < secrets[j].key
				})

				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s):\n", displayPos, entry.Path)
				for _, s := range secrets {
					if s.deleted {
						_, _ = fmt.Fprintf(c.output.Stdout(), "  - %s (deleted)\n", s.key)
					} else {
						_, _ = fmt.Fprintf(c.output.Stdout(), "  - %s\n", s.key)
					}
				}
			}
		}
	}

	return nil
}

// DefragStatsJSON is the JSON output structure for defrag stats
type DefragStatsJSON struct {
	Vault              string  `json:"vault"`
	TotalEntries       int     `json:"total_entries"`
	TotalLines         int     `json:"total_lines"`
	FragmentationRatio float64 `json:"fragmentation_ratio"`
	RecommendDefrag    bool    `json:"recommend_defrag"`
	Reason             string  `json:"reason"`
	Defragmented       bool    `json:"defragmented,omitempty"`
}

// VaultDefrag shows fragmentation stats or performs defragmentation on a single vault
func (c *CLI) VaultDefrag(dryRun bool, jsonOutput bool, skipConfirm bool, vaultPath string, fromIndex int) *Error {
	config := c.vaultResolver.GetConfig()
	vaultPaths := c.vaultResolver.GetVaultPaths()

	// Determine target vault index
	targetIndex := -1

	if vaultPath != "" {
		expandedPath := vault.ExpandPath(vaultPath)
		for i, p := range vaultPaths {
			if vault.ExpandPath(p) == expandedPath {
				targetIndex = i
				break
			}
		}
		if targetIndex == -1 {
			return NewError(fmt.Sprintf("vault path '%s' not found in config", expandedPath), ExitVaultError)
		}
	} else if fromIndex != 0 {
		if fromIndex <= 0 || fromIndex > len(config.Entries) {
			return NewError(fmt.Sprintf("-v index must be between 1 and %d", len(config.Entries)), ExitGeneralError)
		}
		targetIndex = fromIndex - 1
	} else if len(vaultPaths) == 0 {
		return NewError("no vaults configured", ExitVaultError)
	} else if len(vaultPaths) == 1 {
		targetIndex = 0
	} else {
		// Multiple vaults: interactive selection
		idx, selectErr := HandleInteractiveSelection(vaultPaths, "Select vault to defragment:", c.output.Stderr())
		if selectErr != nil {
			return selectErr
		}
		targetIndex = idx
	}

	// Get the vault manager
	entry := config.Entries[targetIndex]
	manager := c.vaultResolver.GetVaultManager(targetIndex)
	if manager == nil {
		return NewError(fmt.Sprintf("failed to load vault: %s", entry.Path), ExitVaultError)
	}

	// Get fragmentation stats
	stats, err := manager.FragmentationStats()
	if err != nil {
		return NewError(fmt.Sprintf("failed to get stats: %v", err), ExitVaultError)
	}

	// Display stats
	if !jsonOutput {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s):\n", targetIndex+1, entry.Path)
		_, _ = fmt.Fprintf(c.output.Stdout(), "  Entries: %d, Lines: %d, Fragmentation: %.1f%%\n",
			stats.TotalEntries, stats.TotalLines, stats.FragmentationRatio*100)
		if stats.RecommendDefrag {
			_, _ = fmt.Fprintf(c.output.Stdout(), "  Status: defragmentation recommended\n")
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "  Status: %s\n", stats.Reason)
		}
	}

	// If dry-run or no defrag needed, we're done
	if dryRun || !stats.RecommendDefrag {
		if jsonOutput {
			return c.outputDefragJSONSingle(entry.Path, stats, false)
		}
		return nil
	}

	// Prompt for confirmation unless --yes
	if !skipConfirm {
		_, _ = fmt.Fprintf(c.output.Stdout(), "\n")
		confirmed, confirmErr := PromptConfirm("Proceed with defragmentation?", c.output.Stderr())
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Defragmentation cancelled.\n")
			if jsonOutput {
				return c.outputDefragJSONSingle(entry.Path, stats, false)
			}
			return nil
		}
	}

	// Perform defragmentation
	newStats, defragErr := manager.Defragment()
	if defragErr != nil {
		return NewError(fmt.Sprintf("defragmentation failed: %v", defragErr), ExitVaultError)
	}

	if !jsonOutput {
		_, _ = fmt.Fprintf(c.output.Stdout(), "\nVault %d (%s): defragmented (%.1f%% -> %.1f%%)\n",
			targetIndex+1, entry.Path, stats.FragmentationRatio*100, newStats.FragmentationRatio*100)
	}

	if jsonOutput {
		return c.outputDefragJSONSingle(entry.Path, newStats, true)
	}

	return nil
}

// outputDefragJSONSingle outputs defrag result for a single vault as JSON
func (c *CLI) outputDefragJSONSingle(vaultPath string, stats *vault.FragmentationStats, defragmented bool) *Error {
	result := DefragStatsJSON{
		Vault:              vaultPath,
		TotalEntries:       stats.TotalEntries,
		TotalLines:         stats.TotalLines,
		FragmentationRatio: stats.FragmentationRatio,
		RecommendDefrag:    stats.RecommendDefrag,
		Reason:             stats.Reason,
		Defragmented:       defragmented,
	}

	encoder := json.NewEncoder(c.output.Stdout())
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
	}
	return nil
}
