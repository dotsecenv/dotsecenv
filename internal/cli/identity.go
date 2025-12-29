package cli

import (
	"encoding/json"
	"fmt"
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
func (c *CLI) IdentityAdd(fingerprint string, all bool) *Error {
	// Validate -v paths against config (warn if not present)
	if len(c.vaultPaths) > 0 {
		fileVaultCfg, err := vault.ParseVaultConfig(c.config.Vault)
		for _, path := range c.vaultPaths {
			expanded := vault.ExpandPath(path)
			found := false
			if err == nil {
				for _, entry := range fileVaultCfg.Entries {
					if vault.ExpandPath(entry.Path) == expanded {
						found = true
						break
					}
				}
			}
			if !found {
				c.Warnf("vault path '%s' is not in configuration", expanded)
			}
		}
	}

	// Determine target indices
	var targetIndices []int

	// Check if any loaded vaults
	loadedConfig := c.vaultResolver.GetConfig()
	if len(loadedConfig.Entries) == 0 {
		return NewError("no vaults configured", ExitConfigError)
	}

	if all {
		// Add to all vaults
		for i := range loadedConfig.Entries {
			targetIndices = append(targetIndices, i)
		}
	} else {
		// Add to first vault only
		targetIndices = append(targetIndices, 0)
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
	skippedCount := 0
	failureCount := 0
	reportMode := all || len(targetIndices) > 1

	for _, idx := range targetIndices {
		vaultPath := loadedConfig.Entries[idx].Path
		displayPos := idx + 1

		// Ensure identity is created
		if newIdentity == nil && createErr == nil {
			newIdentity, createErr = c.createSignedIdentity(publicKeyInfo, fingerprint, signingFP)
		}

		if createErr != nil {
			if reportMode {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): failed: %v\n", displayPos, vaultPath, createErr)
			} else {
				return NewError(fmt.Sprintf("Vault %d (%s): failed: %v", displayPos, vaultPath, createErr), createErr.ExitCode)
			}
			failureCount++
			continue
		}

		manager := c.vaultResolver.GetVaultManager(idx)
		if manager == nil {
			loadErr := c.vaultResolver.GetLoadError(idx)
			errMsg := "unknown error"
			if loadErr != nil {
				errMsg = loadErr.Error()
			}

			if reportMode {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, %s\n", displayPos, vaultPath, errMsg)
				skippedCount++
				continue
			} else {
				return NewError(fmt.Sprintf("failed to access vault: %s", errMsg), ExitVaultError)
			}
		}

		if c.vaultResolver.IdentityExistsInVault(fingerprint, idx) {
			if reportMode {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, already present\n", displayPos, vaultPath)
			} else {
				return NewError(fmt.Sprintf("identity '%s' already exists in vault", fingerprint), ExitGeneralError)
			}
			skippedCount++
			continue
		}

		if err := c.vaultResolver.AddIdentity(*newIdentity, idx); err != nil {
			if reportMode {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped: %v\n", displayPos, vaultPath, err)
				failureCount++
				continue
			} else {
				return NewError(fmt.Sprintf("failed to add identity to vault %d: %v", displayPos, err), ExitVaultError)
			}
		}

		if reportMode {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): added\n", displayPos, vaultPath)
		}
		addedCount++
	}

	if reportMode {
		if addedCount == 0 && failureCount > 0 && skippedCount == 0 {
			return NewError("failed to add identity to any vault", ExitVaultError)
		}
	}

	if addedCount > 0 {
		if saveErr := c.vaultResolver.SaveAll(); saveErr != nil {
			return NewError(fmt.Sprintf("failed to save vault: %v", saveErr), ExitVaultError)
		}

		if !reportMode {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Identity added\n")
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
		return NewError(fmt.Sprintf("identity %s not found in vault %d and will not be added in strict mode\n  run: `dotsecenv vault identity add %s`", fingerprint, index+1, fingerprint), ExitAccessDenied)
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
