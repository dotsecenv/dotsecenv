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

// IdentityListJSON is the JSON output structure for identity list
type IdentityListJSON struct {
	Vault      string             `json:"vault"`
	Identities []IdentityInfoJSON `json:"identities"`
}

// IdentityInfoJSON is the JSON output structure for identity info
type IdentityInfoJSON struct {
	Algorithm     string     `json:"algorithm"`
	AlgorithmBits int        `json:"algorithm_bits"`
	Curve         string     `json:"curve,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Fingerprint   string     `json:"fingerprint"`
	UID           string     `json:"uid"`
}

// IdentityAdd adds an identity to the vault
func (c *CLI) IdentityAdd(fingerprint string, all bool, vaultPath string, fromIndex int) *Error {
	// Determine target indices
	var targetIndices []int

	// Check if any loaded vaults
	loadedConfig := c.vaultResolver.GetConfig()
	if len(loadedConfig.Entries) == 0 {
		return NewError("no vaults configured", ExitConfigError)
	}

	if all {
		// Add to all available vaults (skip non-existent ones)
		availableVaults := c.vaultResolver.GetAvailableVaultPathsWithIndices()
		if len(availableVaults) == 0 {
			return NewError("no vaults available (all configured vaults are missing or inaccessible)", ExitVaultError)
		}
		for _, v := range availableVaults {
			targetIndices = append(targetIndices, v.Index)
		}
	} else {
		// Handle explicit vault selection via -v flag or path
		if vaultPath != "" || fromIndex != 0 {
			targetIndex, resolveErr := c.resolveWritableVaultIndex(vaultPath, fromIndex)
			if resolveErr != nil {
				return resolveErr
			}
			targetIndices = append(targetIndices, targetIndex)
		} else {
			// No explicit vault specified - prompt for selection if multiple vaults
			availableVaults := c.vaultResolver.GetAvailableVaultPathsWithIndices()
			if len(availableVaults) == 0 {
				return NewError("no vaults available (all configured vaults are missing or inaccessible)", ExitVaultError)
			}

			// Auto-select if only one vault is available
			if len(availableVaults) == 1 {
				targetIndices = append(targetIndices, availableVaults[0].Index)
			} else {
				// Show interactive selection for multiple vaults
				displayPaths := make([]string, len(availableVaults))
				for i, v := range availableVaults {
					displayPaths[i] = v.Path
				}

				selectedIndex, selectErr := HandleInteractiveSelection(displayPaths, "Select target vault for identity:", c.output.Stderr())
				if selectErr != nil {
					return selectErr
				}
				targetIndices = append(targetIndices, availableVaults[selectedIndex].Index)
			}
		}
	}

	// Build a set of target indices for quick lookup
	targetSet := make(map[int]bool)
	for _, idx := range targetIndices {
		targetSet[idx] = true
	}

	// Get full config for correct display positions
	fullVaultCfg, _ := vault.ParseVaultConfig(c.config.Vault)

	// In strict mode, pre-flight check: fail if any vault has a parsing error (not just missing)
	if c.Strict {
		// First pass: collect failed vault display positions and their errors
		type vaultError struct {
			displayPos int
			path       string
			errMsg     string
		}
		var failedVaults []vaultError
		var failedDisplayPositions []string

		for idx, entry := range loadedConfig.Entries {
			manager := c.vaultResolver.GetVaultManager(idx)
			if manager == nil {
				loadErr := c.vaultResolver.GetLoadError(idx)
				isNotExist := loadErr != nil && errors.Is(loadErr, os.ErrNotExist)
				if !isNotExist {
					displayPos := idx + 1
					expandedPath := vault.ExpandPath(entry.Path)
					for i, fullEntry := range fullVaultCfg.Entries {
						if vault.ExpandPath(fullEntry.Path) == expandedPath {
							displayPos = i + 1
							break
						}
					}
					errMsg := "unknown error"
					if loadErr != nil {
						errMsg = loadErr.Error()
					}
					failedVaults = append(failedVaults, vaultError{displayPos, entry.Path, errMsg})
					failedDisplayPositions = append(failedDisplayPositions, fmt.Sprintf("%d", displayPos))
				}
			}
		}

		if len(failedVaults) > 0 {
			// Build the list of failing vault numbers for the skip message
			failedVaultsList := failedDisplayPositions[0]
			for i := 1; i < len(failedDisplayPositions); i++ {
				failedVaultsList += ", " + failedDisplayPositions[i]
			}
			vaultWord := "vault"
			if len(failedDisplayPositions) > 1 {
				vaultWord = "vaults"
			}

			// Print header and iterate through all vaults in order
			_, _ = fmt.Fprintf(c.output.Stdout(), "Strict mode: vault errors detected, no changes made\n")
			for idx, entry := range loadedConfig.Entries {
				displayPos := idx + 1
				expandedPath := vault.ExpandPath(entry.Path)
				for i, fullEntry := range fullVaultCfg.Entries {
					if vault.ExpandPath(fullEntry.Path) == expandedPath {
						displayPos = i + 1
						break
					}
				}

				manager := c.vaultResolver.GetVaultManager(idx)
				if manager == nil {
					loadErr := c.vaultResolver.GetLoadError(idx)
					isNotExist := loadErr != nil && errors.Is(loadErr, os.ErrNotExist)
					if !isNotExist {
						errMsg := "unknown error"
						if loadErr != nil {
							errMsg = loadErr.Error()
						}
						_, _ = fmt.Fprintf(c.output.Stdout(), "  Vault %d (%s): error, %s\n", displayPos, entry.Path, errMsg)
					}
					// Skip non-existent vaults silently
				} else if targetSet[idx] {
					_, _ = fmt.Fprintf(c.output.Stdout(), "  Vault %d (%s): would add identity (skipped due to errors in %s %s)\n", displayPos, entry.Path, vaultWord, failedVaultsList)
				}
			}
			return NewError("strict mode error: one or more vaults failed to load", ExitVaultError)
		}
	}

	signingFP := c.getFingerprintFromEnv()
	if signingFP == "" {
		return NewError("no fingerprint configured for signing; run 'dotsecenv init FINGERPRINT' first", ExitFingerprintRequired)
	}

	publicKeyInfo, pubKeyErr := c.gpgClient.GetPublicKeyInfo(fingerprint)
	if pubKeyErr != nil {
		return NewError(fmt.Sprintf("failed to get public key: %v", pubKeyErr), ExitGPGError)
	}

	if publicKeyInfo.AlgorithmBits > 0 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Adding identity: %s (%s %d-bit) %s\n", publicKeyInfo.UID, publicKeyInfo.Algorithm, publicKeyInfo.AlgorithmBits, fingerprint)
	} else {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Adding identity: %s (%s) %s\n", publicKeyInfo.UID, publicKeyInfo.Algorithm, fingerprint)
	}

	// Lazy creation state
	var newIdentity *vault.Identity
	var createErr *Error

	addedCount := 0
	skippedAlreadyPresent := 0
	failureCount := 0
	showAllVaults := all // Only show all vaults when --all flag is used

	// Iterate through configured vaults
	for idx, entry := range loadedConfig.Entries {
		vaultPath := entry.Path
		isTarget := targetSet[idx]

		// Find the correct display position from full config
		displayPos := idx + 1
		expandedPath := vault.ExpandPath(entry.Path)
		for i, fullEntry := range fullVaultCfg.Entries {
			if vault.ExpandPath(fullEntry.Path) == expandedPath {
				displayPos = i + 1
				break
			}
		}

		manager := c.vaultResolver.GetVaultManager(idx)

		// Check if vault is accessible
		if manager == nil {
			loadErr := c.vaultResolver.GetLoadError(idx)
			// Only print non-existing vaults with --all; always print other errors (e.g., parse failures)
			isNotExist := loadErr != nil && errors.Is(loadErr, os.ErrNotExist)
			if showAllVaults || !isNotExist {
				errMsg := "unknown error"
				if loadErr != nil {
					errMsg = loadErr.Error()
				}
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, %s\n", displayPos, vaultPath, errMsg)
			}
			continue
		}

		// Vault exists but not targeted - only show in --all mode
		if !isTarget {
			if showAllVaults {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, not selected\n", displayPos, vaultPath)
			}
			continue
		}

		// Ensure identity is created (lazy)
		if newIdentity == nil && createErr == nil {
			newIdentity, createErr = c.createSignedIdentity(publicKeyInfo, fingerprint, signingFP)
		}

		if createErr != nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): failed, %v\n", displayPos, vaultPath, createErr)
			failureCount++
			continue
		}

		if c.vaultResolver.IdentityExistsInVault(fingerprint, idx) {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, already present\n", displayPos, vaultPath)
			skippedAlreadyPresent++
			continue
		}

		if err := c.vaultResolver.AddIdentity(*newIdentity, idx); err != nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): failed, %v\n", displayPos, vaultPath, err)
			failureCount++
			continue
		}

		_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): added\n", displayPos, vaultPath)
		addedCount++
	}

	// In strict mode, error only if identity was NOT added to any vault
	if c.Strict && addedCount == 0 {
		if skippedAlreadyPresent > 0 {
			return NewError("strict mode error: identity already exists in all viable vaults", ExitGeneralError)
		}
		if failureCount > 0 {
			return NewError("strict mode error: failed to add identity to any vault", ExitVaultError)
		}
	}

	// In non-strict mode, error only if all targets had actual failures (not "already present")
	if !c.Strict && addedCount == 0 && failureCount > 0 && skippedAlreadyPresent == 0 {
		return NewError("failed to add identity to any vault", ExitVaultError)
	}

	if addedCount > 0 {
		if saveErr := c.vaultResolver.SaveAll(); saveErr != nil {
			return NewError(fmt.Sprintf("failed to save vault: %v", saveErr), ExitVaultError)
		}
	}

	return nil
}

// IdentityList lists all identities in all vaults
func (c *CLI) IdentityList(jsonOutput bool) *Error {
	config := c.vaultResolver.GetConfig()

	if jsonOutput {
		var output []IdentityListJSON
		for i, entry := range config.Entries {
			manager := c.vaultResolver.GetVaultManager(i)

			if manager != nil {
				entryAbs, _ := filepath.Abs(entry.Path)
				managerAbs, _ := filepath.Abs(manager.Path())
				if entryAbs != managerAbs {
					manager = nil
				}
			}

			if manager != nil {
				vaultData := manager.Get()
				identities := []IdentityInfoJSON{}

				sortedIdentities := make([]vault.Identity, len(vaultData.Identities))
				copy(sortedIdentities, vaultData.Identities)
				sort.Slice(sortedIdentities, func(i, j int) bool {
					return sortedIdentities[i].UID < sortedIdentities[j].UID
				})

				for _, id := range sortedIdentities {
					identities = append(identities, IdentityInfoJSON{
						Algorithm:     id.Algorithm,
						AlgorithmBits: id.AlgorithmBits,
						Curve:         id.Curve,
						CreatedAt:     id.CreatedAt,
						ExpiresAt:     id.ExpiresAt,
						Fingerprint:   id.Fingerprint,
						UID:           id.UID,
					})
				}

				output = append(output, IdentityListJSON{
					Vault:      entry.Path,
					Identities: identities,
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

	for i, entry := range config.Entries {
		manager := c.vaultResolver.GetVaultManager(i)

		if manager != nil {
			entryAbs, _ := filepath.Abs(entry.Path)
			managerAbs, _ := filepath.Abs(manager.Path())
			if entryAbs != managerAbs {
				manager = nil
			}
		}

		if manager != nil {
			displayPos := i + 1
			// Attempt to resolve canonical index from global config
			if globalVaultCfg, err := vault.ParseVaultConfig(c.config.Vault); err == nil {
				currentPath := vault.ExpandPath(entry.Path)
				if abs, err := filepath.Abs(currentPath); err == nil {
					currentPath = abs
				}
				for k, gEntry := range globalVaultCfg.Entries {
					gPath := vault.ExpandPath(gEntry.Path)
					if abs, err := filepath.Abs(gPath); err == nil {
						gPath = abs
					}
					if currentPath == gPath {
						displayPos = k + 1
						break
					}
				}
			}
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s)\n", displayPos, entry.Path)
			vaultData := manager.Get()

			if len(vaultData.Identities) == 0 {
				_, _ = fmt.Fprintf(c.output.Stdout(), "  (No identities)\n")
			} else {
				sortedIdentities := make([]vault.Identity, len(vaultData.Identities))
				copy(sortedIdentities, vaultData.Identities)
				sort.Slice(sortedIdentities, func(i, j int) bool {
					return sortedIdentities[i].UID < sortedIdentities[j].UID
				})

				for _, id := range sortedIdentities {
					_, _ = fmt.Fprintf(c.output.Stdout(), "  - UID: %s\n", id.UID)
					_, _ = fmt.Fprintf(c.output.Stdout(), "    Fingerprint: %s\n", id.Fingerprint)

					algoStr := id.Algorithm
					if id.AlgorithmBits > 0 {
						algoStr += fmt.Sprintf(" (%d bits)", id.AlgorithmBits)
					}
					if id.Curve != "" {
						algoStr += fmt.Sprintf(" Curve: %s", id.Curve)
					}
					_, _ = fmt.Fprintf(c.output.Stdout(), "    Algorithm: %s\n", algoStr)
					_, _ = fmt.Fprintf(c.output.Stdout(), "    Created: %s\n", id.CreatedAt.Format(time.RFC3339))
					if id.ExpiresAt != nil {
						_, _ = fmt.Fprintf(c.output.Stdout(), "    Expires: %s\n", id.ExpiresAt.Format(time.RFC3339))
					}
					_, _ = fmt.Fprintf(c.output.Stdout(), "\n")
				}
			}
		}
	}
	return nil
}

// ensureIdentityInVault ensures the identity exists in the specified vault index
func (c *CLI) ensureIdentityInVault(fingerprint string, index int) *Error {
	if c.vaultResolver.IdentityExistsInVault(fingerprint, index) {
		return nil
	}

	if c.Strict {
		return NewError(fmt.Sprintf("strict mode error: identity %s not found in vault %d and will not be added\n  run: `dotsecenv vault identity add %s`", fingerprint, index+1, fingerprint), ExitAccessDenied)
	}

	_, _ = fmt.Fprintf(c.output.Stderr(), "Auto-adding identity %s to vault %d...\n", fingerprint, index+1)

	publicKeyInfo, pubKeyErr := c.gpgClient.GetPublicKeyInfo(fingerprint)
	if pubKeyErr != nil {
		return NewError(fmt.Sprintf("failed to get public key: %v", pubKeyErr), ExitGPGError)
	}

	if !c.config.IsAlgorithmAllowed(publicKeyInfo.Algorithm, publicKeyInfo.AlgorithmBits) {
		return NewError(fmt.Sprintf("algorithm not allowed: %s (%d bits)\n%s", publicKeyInfo.Algorithm, publicKeyInfo.AlgorithmBits, c.config.GetAllowedAlgorithmsString()), ExitAlgorithmNotAllowed)
	}

	if !publicKeyInfo.CanEncrypt {
		return NewError(fmt.Sprintf("key %s is not capable of encryption (signing-only key).\nPlease ensure your key has an encryption subkey.", fingerprint), ExitGPGError)
	}

	now := time.Now().UTC()
	algo, curve := c.gpgClient.ExtractAlgorithmAndCurve(publicKeyInfo.Algorithm)

	newIdentity := vault.Identity{
		AddedAt:       now,
		Fingerprint:   fingerprint,
		UID:           publicKeyInfo.UID,
		Algorithm:     algo,
		AlgorithmBits: publicKeyInfo.AlgorithmBits,
		Curve:         curve,
		CreatedAt:     c.gpgClient.GetKeyCreationTime(fingerprint),
		ExpiresAt:     publicKeyInfo.ExpiresAt,
		PublicKey:     publicKeyInfo.PublicKeyBase64,
		SignedBy:      fingerprint,
	}

	newIdentity.Hash = ComputeIdentityHash(&newIdentity)

	signature, signErr := c.gpgClient.SignDataWithAgent(fingerprint, []byte(newIdentity.Hash))
	if signErr != nil {
		return NewError(fmt.Sprintf("failed to sign identity: %v", signErr), ExitGPGError)
	}
	newIdentity.Signature = signature

	if err := c.vaultResolver.AddIdentity(newIdentity, index); err != nil {
		return NewError(fmt.Sprintf("failed to add identity: %v", err), ExitVaultError)
	}

	return nil
}
