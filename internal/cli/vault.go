package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// resolveWritableVaultIndex resolves which vault to write to based on vaultPath and fromIndex.
// If neither is specified, it performs interactive selection from available vaults.
// The prompt parameter customizes the interactive selection prompt (empty uses default).
// Returns the 0-based vault index or an error.
func (c *CLI) resolveWritableVaultIndex(vaultPath string, fromIndex int, prompt ...string) (int, *Error) {
	if vaultPath != "" {
		expandedPath := vault.ExpandPath(vaultPath)

		// Check if file exists/writable
		if _, err := os.Stat(expandedPath); err != nil {
			if os.IsNotExist(err) {
				return -1, NewError(fmt.Sprintf("vault file does not exist: %s", expandedPath), ExitVaultError)
			}
			return -1, NewError(fmt.Sprintf("cannot access vault file: %v", err), ExitVaultError)
		}
		f, openErr := os.OpenFile(expandedPath, os.O_WRONLY, 0)
		if openErr != nil {
			return -1, NewError(fmt.Sprintf("vault file is not writable: %s", expandedPath), ExitVaultError)
		}
		_ = f.Close()

		// Find in loaded paths
		loadedPaths := c.vaultResolver.GetVaultPaths()
		for i, p := range loadedPaths {
			if vault.ExpandPath(p) == expandedPath {
				return i, nil
			}
		}
		return -1, NewError(fmt.Sprintf("vault path '%s' is not loaded in current session", expandedPath), ExitGeneralError)
	}

	if fromIndex != 0 {
		configEntries := c.vaultResolver.GetConfig().Entries
		if fromIndex <= 0 {
			return -1, NewError("-v index must be a positive integer (N >= 1)", ExitGeneralError)
		}
		if fromIndex > len(configEntries) {
			_, _ = fmt.Fprintf(c.output.Stderr(), "Configured vaults:\n")
			for i, p := range configEntries {
				_, _ = fmt.Fprintf(c.output.Stderr(), "  %d: %s\n", i+1, p.Path)
			}
			return -1, NewError(fmt.Sprintf("-v index %d exceeds number of configured vaults (%d)", fromIndex, len(configEntries)), ExitGeneralError)
		}
		return fromIndex - 1, nil
	}

	// No flags - interactive selection or default
	// Only show vaults that are actually available (exist and were loaded successfully)
	availableVaults := c.vaultResolver.GetAvailableVaultPathsWithIndices()
	if len(availableVaults) == 0 {
		return -1, NewError("no vaults available", ExitVaultError)
	}
	if len(availableVaults) == 1 {
		return availableVaults[0].Index, nil
	}

	// Multiple vaults: interactive selection
	// Extract just the paths for display
	displayPaths := make([]string, len(availableVaults))
	for i, v := range availableVaults {
		displayPaths[i] = v.Path
	}

	// Use custom prompt if provided, otherwise default
	selectionPrompt := "Multiple vaults configured. Select target vault:"
	if len(prompt) > 0 && prompt[0] != "" {
		selectionPrompt = prompt[0]
	}

	selectedIndex, selectErr := HandleInteractiveSelection(displayPaths, selectionPrompt, c.output.Stderr())
	if selectErr != nil {
		return -1, selectErr
	}
	// Map back to the original configuration index
	return availableVaults[selectedIndex].Index, nil
}

// checkVaultWritable verifies that a vault file and its directory are writable.
// This should be called before operations that modify the vault file.
func checkVaultWritable(vaultPath string) *Error {
	expandedPath := vault.ExpandPath(vaultPath)

	// Check file is writable
	f, openErr := os.OpenFile(expandedPath, os.O_WRONLY, 0)
	if openErr != nil {
		return NewError(fmt.Sprintf("vault file is not writable: %s", expandedPath), ExitVaultError)
	}
	_ = f.Close()

	// Check directory is writable (for temp file creation during atomic writes)
	dir := filepath.Dir(expandedPath)
	tmpPath := filepath.Join(dir, ".dotsecenv-write-test")
	tmpFile, tmpErr := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if tmpErr != nil {
		return NewError(fmt.Sprintf("vault directory is not writable: %s", dir), ExitVaultError)
	}
	_ = tmpFile.Close()
	_ = os.Remove(tmpPath)

	return nil
}

// VaultDescribeSecretJSON represents a secret in the vault describe JSON output
type VaultDescribeSecretJSON struct {
	Key     string `json:"key"`
	Deleted bool   `json:"deleted,omitempty"`
}

// VaultDescribeIdentityJSON represents an identity in the vault describe JSON output
type VaultDescribeIdentityJSON struct {
	UID           string     `json:"uid"`
	Fingerprint   string     `json:"fingerprint"`
	Algorithm     string     `json:"algorithm"`
	AlgorithmBits int        `json:"algorithm_bits"`
	Curve         string     `json:"curve,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// VaultDescribeJSON is the JSON output structure for vault describe
type VaultDescribeJSON struct {
	Position   int                         `json:"position"`
	Vault      string                      `json:"vault"`
	Identities []VaultDescribeIdentityJSON `json:"identities"`
	Secrets    []VaultDescribeSecretJSON   `json:"secrets"`
}

// VaultDescribe lists all vaults with their identities and secrets
func (c *CLI) VaultDescribe(jsonOutput bool) *Error {
	config := c.vaultResolver.GetConfig()

	if jsonOutput {
		var output []VaultDescribeJSON
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

				// Build identities list
				var identities []VaultDescribeIdentityJSON
				sortedIdentities := make([]vault.Identity, len(vaultData.Identities))
				copy(sortedIdentities, vaultData.Identities)
				sort.Slice(sortedIdentities, func(i, j int) bool {
					return sortedIdentities[i].UID < sortedIdentities[j].UID
				})
				for _, id := range sortedIdentities {
					identities = append(identities, VaultDescribeIdentityJSON{
						UID:           id.UID,
						Fingerprint:   id.Fingerprint,
						Algorithm:     id.Algorithm,
						AlgorithmBits: id.AlgorithmBits,
						Curve:         id.Curve,
						CreatedAt:     id.CreatedAt,
						ExpiresAt:     id.ExpiresAt,
					})
				}

				// Build secrets list
				var secrets []VaultDescribeSecretJSON
				for _, s := range vaultData.Secrets {
					secrets = append(secrets, VaultDescribeSecretJSON{
						Key:     s.Key,
						Deleted: s.IsDeleted(),
					})
				}
				sort.Slice(secrets, func(i, j int) bool {
					return secrets[i].Key < secrets[j].Key
				})

				output = append(output, VaultDescribeJSON{
					Position:   i + 1,
					Vault:      entry.Path,
					Identities: identities,
					Secrets:    secrets,
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
			loadErr := c.vaultResolver.GetLoadError(i)
			isNotExist := loadErr != nil && errors.Is(loadErr, os.ErrNotExist)
			if isNotExist {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped (not present)\n", displayPos, entry.Path)
			} else if loadErr != nil {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped (err: %v)\n", displayPos, entry.Path, loadErr)
			} else {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped (not loaded)\n", displayPos, entry.Path)
			}
		} else {
			vaultData := manager.Get()
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s):\n", displayPos, entry.Path)

			// Print identities
			_, _ = fmt.Fprintf(c.output.Stdout(), "  Identities:\n")
			if len(vaultData.Identities) == 0 {
				_, _ = fmt.Fprintf(c.output.Stdout(), "    (none)\n")
			} else {
				sortedIdentities := make([]vault.Identity, len(vaultData.Identities))
				copy(sortedIdentities, vaultData.Identities)
				sort.Slice(sortedIdentities, func(i, j int) bool {
					return sortedIdentities[i].UID < sortedIdentities[j].UID
				})
				for _, id := range sortedIdentities {
					_, _ = fmt.Fprintf(c.output.Stdout(), "    - %s (%s)\n", id.UID, id.Fingerprint)
				}
			}

			// Print secrets
			_, _ = fmt.Fprintf(c.output.Stdout(), "  Secrets:\n")
			if len(vaultData.Secrets) == 0 {
				_, _ = fmt.Fprintf(c.output.Stdout(), "    (none)\n")
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
				for _, s := range secrets {
					if s.deleted {
						_, _ = fmt.Fprintf(c.output.Stdout(), "    - %s (deleted)\n", s.key)
					} else {
						_, _ = fmt.Fprintf(c.output.Stdout(), "    - %s\n", s.key)
					}
				}
			}
		}
	}

	return nil
}

// isCI returns true if running in a CI environment
func isCI() bool {
	// Common CI environment variables
	ciEnvVars := []string{
		"CI",
		"GITHUB_ACTIONS",
		"GITLAB_CI",
		"JENKINS_URL",
		"CIRCLECI",
		"TRAVIS",
		"BUILDKITE",
		"DRONE",
		"TF_BUILD",         // Azure Pipelines
		"TEAMCITY_VERSION", // TeamCity
		"BITBUCKET_BUILD_NUMBER",
	}
	for _, env := range ciEnvVars {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

// DoctorCheckJSON represents a single health check in JSON output
type DoctorCheckJSON struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "ok", "warning", "error"
	Message string `json:"message,omitempty"`
	Details string `json:"details,omitempty"`
}

// DoctorResultJSON is the JSON output structure for doctor
type DoctorResultJSON struct {
	Status string            `json:"status"` // "healthy", "warning", "error"
	Checks []DoctorCheckJSON `json:"checks"`
}

// upgradeCandidate tracks a vault that needs format upgrade
type upgradeCandidate struct {
	index          int
	path           string
	currentVersion int
}

// defragCandidate tracks a vault that needs defragmentation
type defragCandidate struct {
	index int
	path  string
	stats *vault.FragmentationStats
}

// VaultDoctor runs health checks on the vault configuration and environment.
// In CI environments, interactive prompts are skipped automatically.
func (c *CLI) VaultDoctor(jsonOutput bool, vaultPath string, fromIndex int) *Error {
	cfg := c.vaultResolver.GetConfig()

	var checks []DoctorCheckJSON
	overallStatus := "healthy"
	var upgradeCandidates []upgradeCandidate
	var defragCandidates []defragCandidate

	// Check 1: GPG agent availability
	gpgStatus := "ok"
	gpgMessage := "gpg-agent is available"
	gpgDetails := ""
	if !c.gpgClient.IsAgentAvailable() {
		gpgStatus = "error"
		gpgMessage = "gpg-agent is not available"
		gpgDetails = "See: https://dotsecenv.com/docs/troubleshooting/gpg-agent"
		overallStatus = "error"
	}
	checks = append(checks, DoctorCheckJSON{
		Name:    "gpg_agent",
		Status:  gpgStatus,
		Message: gpgMessage,
		Details: gpgDetails,
	})

	// Check 2: Vault format versions
	for i, entry := range cfg.Entries {
		manager := c.vaultResolver.GetVaultManager(i)
		if manager == nil {
			loadErr := c.vaultResolver.GetLoadError(i)
			if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
				checks = append(checks, DoctorCheckJSON{
					Name:    fmt.Sprintf("vault_%d_format", i+1),
					Status:  "error",
					Message: fmt.Sprintf("%s: failed to load", entry.Path),
					Details: loadErr.Error(),
				})
				if overallStatus != "error" {
					overallStatus = "error"
				}
			}
			continue
		}

		currentVersion, err := vault.DetectVaultVersion(entry.Path)
		if err != nil {
			checks = append(checks, DoctorCheckJSON{
				Name:    fmt.Sprintf("vault_%d_format", i+1),
				Status:  "error",
				Message: fmt.Sprintf("%s: failed to detect version", entry.Path),
				Details: err.Error(),
			})
			if overallStatus != "error" {
				overallStatus = "error"
			}
			continue
		}

		if currentVersion == 0 {
			// Empty vault - this is fine
			checks = append(checks, DoctorCheckJSON{
				Name:    fmt.Sprintf("vault_%d_format", i+1),
				Status:  "ok",
				Message: fmt.Sprintf("%s: empty (will use latest format)", entry.Path),
			})
		} else if currentVersion < vault.LatestFormatVersion {
			checks = append(checks, DoctorCheckJSON{
				Name:    fmt.Sprintf("vault_%d_format", i+1),
				Status:  "warning",
				Message: fmt.Sprintf("%s: format v%d (latest: v%d)", entry.Path, currentVersion, vault.LatestFormatVersion),
			})
			if overallStatus == "healthy" {
				overallStatus = "warning"
			}
			upgradeCandidates = append(upgradeCandidates, upgradeCandidate{
				index:          i,
				path:           entry.Path,
				currentVersion: currentVersion,
			})
		} else {
			checks = append(checks, DoctorCheckJSON{
				Name:    fmt.Sprintf("vault_%d_format", i+1),
				Status:  "ok",
				Message: fmt.Sprintf("%s: format v%d (latest)", entry.Path, currentVersion),
			})
		}
	}

	// Check 3: Vault fragmentation
	// Determine target vault(s) for fragmentation check
	var targetIndices []int
	if vaultPath != "" || fromIndex != 0 {
		// Specific vault selected
		targetIndex, resolveErr := c.resolveWritableVaultIndex(vaultPath, fromIndex)
		if resolveErr != nil {
			return resolveErr
		}
		targetIndices = []int{targetIndex}
	} else {
		// Check all available vaults
		available := c.vaultResolver.GetAvailableVaultPathsWithIndices()
		for _, v := range available {
			targetIndices = append(targetIndices, v.Index)
		}
	}

	for _, idx := range targetIndices {
		entry := cfg.Entries[idx]
		manager := c.vaultResolver.GetVaultManager(idx)
		if manager == nil {
			continue
		}

		stats, err := manager.FragmentationStats()
		if err != nil {
			checks = append(checks, DoctorCheckJSON{
				Name:    fmt.Sprintf("vault_%d_fragmentation", idx+1),
				Status:  "error",
				Message: fmt.Sprintf("%s: failed to get stats", entry.Path),
				Details: err.Error(),
			})
			if overallStatus != "error" {
				overallStatus = "error"
			}
			continue
		}

		fragStatus := "ok"
		fragMessage := fmt.Sprintf("%s: %.1f%% fragmentation", entry.Path, stats.FragmentationRatio*100)

		if stats.RecommendDefrag {
			fragStatus = "warning"
			fragMessage = fmt.Sprintf("%s: %.1f%% fragmentation (high)", entry.Path, stats.FragmentationRatio*100)
			if overallStatus == "healthy" {
				overallStatus = "warning"
			}
			defragCandidates = append(defragCandidates, defragCandidate{
				index: idx,
				path:  entry.Path,
				stats: stats,
			})
		}

		checks = append(checks, DoctorCheckJSON{
			Name:    fmt.Sprintf("vault_%d_fragmentation", idx+1),
			Status:  fragStatus,
			Message: fragMessage,
		})
	}

	// Output results
	if jsonOutput {
		result := DoctorResultJSON{
			Status: overallStatus,
			Checks: checks,
		}
		encoder := json.NewEncoder(c.output.Stdout())
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
		}
		return nil
	}

	// Text output
	_, _ = fmt.Fprintf(c.output.Stdout(), "Health checks:\n")
	for _, check := range checks {
		var statusIcon string
		switch check.Status {
		case "warning":
			statusIcon = "!"
		case "error":
			statusIcon = "✗"
		default:
			statusIcon = "✓"
		}
		_, _ = fmt.Fprintf(c.output.Stdout(), "  [%s] %s\n", statusIcon, check.Message)
		if check.Details != "" {
			_, _ = fmt.Fprintf(c.output.Stdout(), "      %s\n", check.Details)
		}
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "\nStatus: %s\n", overallStatus)

	// In CI environments, skip all interactive prompts
	if isCI() {
		return nil
	}

	// Offer to upgrade vaults that need it
	for _, candidate := range upgradeCandidates {
		expandedPath := vault.ExpandPath(candidate.path)
		_, _ = fmt.Fprintf(c.output.Stdout(), "\n")
		confirmed, confirmErr := PromptConfirm(fmt.Sprintf("Upgrade vault %s from v%d to v%d?", expandedPath, candidate.currentVersion, vault.LatestFormatVersion), c.output.Stderr())
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			continue
		}

		// Perform the upgrade
		if upgradeErr := c.performVaultUpgrade(candidate.index, candidate.path, candidate.currentVersion); upgradeErr != nil {
			return upgradeErr
		}
	}

	// Offer to defragment vaults that need it
	for _, candidate := range defragCandidates {
		expandedPath := vault.ExpandPath(candidate.path)
		_, _ = fmt.Fprintf(c.output.Stdout(), "\n")
		confirmed, confirmErr := PromptConfirm(fmt.Sprintf("Defragment vault %s?", expandedPath), c.output.Stderr())
		if confirmErr != nil {
			return confirmErr
		}
		if !confirmed {
			continue
		}

		// Perform defragmentation
		manager := c.vaultResolver.GetVaultManager(candidate.index)
		newStats, defragErr := manager.Defragment()
		if defragErr != nil {
			return NewError(fmt.Sprintf("defragmentation failed: %v", defragErr), ExitVaultError)
		}

		_, _ = fmt.Fprintf(c.output.Stdout(), "Defragmented %s (%.1f%% -> %.1f%%)\n",
			expandedPath, candidate.stats.FragmentationRatio*100, newStats.FragmentationRatio*100)
	}

	return nil
}

// performVaultUpgrade upgrades a single vault to the latest format version
func (c *CLI) performVaultUpgrade(index int, vaultPath string, currentVersion int) *Error {
	expandedPath := vault.ExpandPath(vaultPath)

	// Verify writability before proceeding
	if writeErr := checkVaultWritable(vaultPath); writeErr != nil {
		return writeErr
	}

	// Perform the upgrade
	writer, err := vault.NewWriter(expandedPath)
	if err != nil {
		return NewError(fmt.Sprintf("failed to open vault for upgrade: %v", err), ExitVaultError)
	}

	// Read entire vault
	vaultData, err := writer.ReadVault()
	if err != nil {
		return NewError(fmt.Sprintf("failed to read vault for upgrade: %v", err), ExitVaultError)
	}

	// Rewrite vault using latest version format
	if err := writer.RewriteFromVaultWithVersion(vaultData, vault.LatestFormatVersion); err != nil {
		return NewError(fmt.Sprintf("failed to upgrade vault: %v", err), ExitVaultError)
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Upgraded %s from v%d to v%d\n",
		expandedPath, currentVersion, vault.LatestFormatVersion)

	return nil
}
