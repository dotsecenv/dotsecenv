package cli

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// SecretValueJSON is the JSON output structure for secret values
type SecretValueJSON struct {
	AddedAt time.Time `json:"added_at"`
	Value   string    `json:"value"`
	Vault   string    `json:"vault,omitempty"`
}

// SecretPut stores a secret in the vault
func (c *CLI) SecretPut(secretKeyArg, vaultPath string, fromIndex int) *Error {
	// Validate and normalize secret key
	normalizedKey, normErr := vault.NormalizeSecretKey(secretKeyArg)
	if normErr != nil {
		return NewError(vault.FormatSecretKeyError(normErr), ExitValidationError)
	}

	fp, err := c.checkFingerprintRequired("secret put")
	if err != nil {
		return err
	}

	secretKey := normalizedKey
	targetIndex := -1

	if vaultPath != "" {
		// -v PATH specified
		expandedPath := vault.ExpandPath(vaultPath)

		// Check if file exists/writable
		_, statErr := os.Stat(expandedPath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return NewError(fmt.Sprintf("vault file does not exist: %s", expandedPath), ExitVaultError)
			}
			return NewError(fmt.Sprintf("cannot access vault file: %v", statErr), ExitVaultError)
		}
		f, openErr := os.OpenFile(expandedPath, os.O_WRONLY, 0)
		if openErr != nil {
			return NewError(fmt.Sprintf("vault file is not writable: %s", expandedPath), ExitVaultError)
		}
		_ = f.Close()

		// Check if path is in loaded config
		loadedPaths := c.vaultResolver.GetVaultPaths()
		found := false
		for i, p := range loadedPaths {
			if vault.ExpandPath(p) == expandedPath {
				targetIndex = i
				found = true
				break
			}
		}

		if !found {
			return NewError(fmt.Sprintf("vault path '%s' is not loaded in current session", expandedPath), ExitGeneralError)
		}

	} else if fromIndex != 0 {
		// -v N specified
		configEntries := c.vaultResolver.GetConfig().Entries
		if fromIndex <= 0 {
			return NewError("-v index must be a positive integer (N >= 1)", ExitGeneralError)
		}
		if fromIndex > len(configEntries) {
			_, _ = fmt.Fprintf(c.output.Stderr(), "Configured vaults:\n")
			for i, p := range configEntries {
				_, _ = fmt.Fprintf(c.output.Stderr(), "  %d: %s\n", i+1, p.Path)
			}
			return NewError(fmt.Sprintf("-v index %d exceeds number of configured vaults (%d)", fromIndex, len(configEntries)), ExitGeneralError)
		}
		targetIndex = fromIndex - 1

	} else {
		// No flags. Interactive selection or default.
		vaultPaths := c.vaultResolver.GetVaultPaths()

		if len(vaultPaths) == 0 {
			return NewError("no vaults configured", ExitVaultError)
		} else if len(vaultPaths) == 1 {
			targetIndex = 0
		} else {
			// Multiple vaults: interactive selection
			selectedIndex, selectErr := HandleInteractiveSelection(vaultPaths, "Multiple vaults configured. Select target vault:", c.output.Stderr())
			if selectErr != nil {
				return selectErr
			}
			targetIndex = selectedIndex
		}
	}

	if ensureErr := c.ensureIdentityInVault(fp, targetIndex); ensureErr != nil {
		return ensureErr
	}

	identity := c.vaultResolver.GetIdentityByFingerprint(fp)
	if identity == nil {
		return NewError(fmt.Sprintf("identity not found in vault\n  run: `dotsecenv vault identity add %s`", fp), ExitAccessDenied)
	}

	// Check if secret exists and if we have access to the latest value
	existingSecret := c.vaultResolver.GetSecretByKeyFromVault(targetIndex, secretKey)
	if existingSecret != nil && len(existingSecret.Values) > 0 {
		latestValue := existingSecret.Values[len(existingSecret.Values)-1]
		if !slices.Contains(latestValue.AvailableTo, fp) {
			return NewError(fmt.Sprintf("access denied: you do not have access to the latest value of secret '%s'", secretKey), ExitAccessDenied)
		}
	}

	isTTY := false
	if f, ok := c.stdin.(*os.File); ok {
		isTTY = term.IsTerminal(int(f.Fd()))
	}

	if isTTY {
		_, _ = fmt.Fprintf(c.output.Stderr(), "Enter secret value (input will be redacted): ")
	}
	secretValue, readErr := c.readSecretFromStdin()
	if readErr != nil {
		return NewError(fmt.Sprintf("failed to read secret: %v", readErr), ExitGeneralError)
	}

	encryptedArmored, encErr := c.gpgClient.EncryptToRecipients(
		[]byte(secretValue),
		[]string{identity.PublicKey},
		nil,
	)
	if encErr != nil {
		return NewError(fmt.Sprintf("failed to encrypt secret: %v", encErr), ExitGeneralError)
	}

	encryptedBase64 := base64.StdEncoding.EncodeToString([]byte(encryptedArmored))
	now := time.Now().UTC()

	secretMetadata := fmt.Sprintf("secret:%s:%s:%s", now.Format(time.RFC3339Nano), secretKey, fp)
	secretHash := ComputeHash([]byte(secretMetadata), identity.AlgorithmBits)
	secretSig, sigErr := c.gpgClient.SignDataWithAgent(fp, []byte(secretHash))
	if sigErr != nil {
		return NewError(fmt.Sprintf("failed to sign secret: %v", sigErr), ExitGeneralError)
	}

	availableTo := strings.Join([]string{fp}, ",")
	valueMetadata := fmt.Sprintf("value:%s:%s:%s:%s:%s", now.Format(time.RFC3339Nano), secretKey, availableTo, fp, encryptedBase64)
	valueHash := ComputeHash([]byte(valueMetadata), identity.AlgorithmBits)
	valueSig, valueSigErr := c.gpgClient.SignDataWithAgent(fp, []byte(valueHash))
	if valueSigErr != nil {
		return NewError(fmt.Sprintf("failed to sign secret value: %v", valueSigErr), ExitGeneralError)
	}

	newSecret := vault.Secret{
		AddedAt:   now,
		Hash:      secretHash,
		Key:       secretKey,
		Signature: secretSig,
		SignedBy:  fp,
		Values: []vault.SecretValue{
			{
				AddedAt:     now,
				AvailableTo: []string{fp},
				Hash:        valueHash,
				Signature:   valueSig,
				SignedBy:    fp,
				Value:       encryptedBase64,
			},
		},
	}

	if err := c.vaultResolver.AddSecret(newSecret, targetIndex); err != nil {
		return NewError(fmt.Sprintf("failed to add secret: %v", err), ExitVaultError)
	}

	if saveErr := c.vaultResolver.SaveVault(targetIndex); saveErr != nil {
		return NewError(fmt.Sprintf("failed to save vault: %v", saveErr), ExitVaultError)
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Secret '%s' stored successfully\n", secretKey)
	return nil
}

// SecretGet retrieves a secret from the vault.
// If c.Strict is true (from config), only returns a value if the user has access to the LATEST value of the secret.
func (c *CLI) SecretGet(secretKey string, all bool, last bool, jsonOutput bool, vaultPath string, fromIndex int) *Error {
	// Validate secret key format
	if _, err := vault.NormalizeSecretKey(secretKey); err != nil {
		return NewError(vault.FormatSecretKeyError(err), ExitValidationError)
	}

	fp, err := c.checkFingerprintRequired("secret get")
	if err != nil {
		return err
	}

	// Handle --last + -v combination warning/error
	if last && (vaultPath != "" || fromIndex != 0) {
		vaultPaths := c.vaultResolver.GetVaultPaths()
		var targetDesc string
		if vaultPath != "" {
			targetDesc = vaultPath
		} else if fromIndex > 0 && fromIndex <= len(vaultPaths) {
			targetDesc = fmt.Sprintf("vault %d (%s)", fromIndex, vaultPaths[fromIndex-1])
		} else {
			targetDesc = fmt.Sprintf("vault %d", fromIndex)
		}
		if c.Strict {
			return NewError(fmt.Sprintf("strict mode: --last and -v cannot be used together; omit -v to search all vaults or remove --last to use %s", targetDesc), ExitGeneralError)
		}
		_, _ = fmt.Fprintf(c.output.Stderr(), "warning: --last is ignored when -v is specified; returning latest value from %s. Omit -v to search all vaults.\n", targetDesc)
		last = false
	}

	targetIndex := -1

	if vaultPath != "" {
		expandedPath := vault.ExpandPath(vaultPath)
		// Check if in config
		loadedPaths := c.vaultResolver.GetVaultPaths()
		found := false
		for i, p := range loadedPaths {
			if vault.ExpandPath(p) == expandedPath {
				targetIndex = i
				found = true
				break
			}
		}
		if !found {
			// Check if file exists for better error message
			if _, err := os.Stat(expandedPath); err != nil {
				return NewError(fmt.Sprintf("vault file does not exist: %s", expandedPath), ExitVaultError)
			}
			return NewError(fmt.Sprintf("vault path '%s' not found in resolver", expandedPath), ExitVaultError)
		}
	} else if fromIndex != 0 {
		configEntries := c.vaultResolver.GetConfig().Entries
		if fromIndex <= 0 || fromIndex > len(configEntries) {
			return NewError(fmt.Sprintf("-v index must be a positive integer between 1 and %d", len(configEntries)), ExitGeneralError)
		}
		targetIndex = fromIndex - 1
	}

	// Get secret based on mode
	if targetIndex != -1 {
		// Single vault mode
		return c.vaultGetFromIndex(secretKey, targetIndex, all, jsonOutput, fp)
	}

	if last {
		return c.vaultGetLastFromAllVaults(secretKey, jsonOutput, fp)
	}

	var decryptedValues []string
	var decryptedValuesWithTime []SecretValueJSON
	var secret *vault.SecretValue
	var secretVaultPath string

	if all {
		// Collect all values from ALL vaults
		var allValues []struct {
			Value     vault.SecretValue
			VaultPath string
		}

		// Search all vaults
		for i, entry := range c.vaultResolver.GetConfig().Entries {
			secretObj := c.vaultResolver.GetSecretByKeyFromVault(i, secretKey)
			if secretObj != nil {
				for j := range secretObj.Values {
					allValues = append(allValues, struct {
						Value     vault.SecretValue
						VaultPath string
					}{secretObj.Values[j], entry.Path})
				}
			}
		}

		if len(allValues) == 0 {
			return NewError(fmt.Sprintf("secret '%s' not found in any vault", secretKey), ExitVaultError)
		}

		// Sort by AddedAt descending (newest first)
		sort.Slice(allValues, func(i, j int) bool {
			return allValues[i].Value.AddedAt.After(allValues[j].Value.AddedAt)
		})

		// Decrypt all values
		for _, item := range allValues {
			val := item.Value

			hasAccess := false
			for _, authorizedFp := range val.AvailableTo {
				if authorizedFp == fp {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				continue
			}

			encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(val.Value)
			if decodeErr != nil {
				if c.Strict {
					return NewError(fmt.Sprintf("strict mode: failed to decode value from %s: %v", val.AddedAt, decodeErr), ExitGeneralError)
				}
				c.Warnf("failed to decode value from %s: %v", val.AddedAt, decodeErr)
				continue
			}

			plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
			if decErr != nil {
				if c.Strict {
					return NewError(fmt.Sprintf("strict mode: failed to decrypt value from %s: %v", val.AddedAt, decErr), ExitGPGError)
				}
				c.Warnf("failed to decrypt value from %s: %v", val.AddedAt, decErr)
				continue
			}
			valStr := string(plaintext)
			decryptedValues = append(decryptedValues, valStr)
			decryptedValuesWithTime = append(decryptedValuesWithTime, SecretValueJSON{
				AddedAt: val.AddedAt,
				Value:   valStr,
				Vault:   item.VaultPath,
			})
		}
	} else {
		// Default mode: search all vaults in order, return from first vault that has it
		// Use GetAccessibleSecretFromAnyVault to find a value THIS user can access
		// If c.Strict is true, only the latest value is considered; otherwise fallback to older values
		var errGet error
		secret, errGet = c.vaultResolver.GetAccessibleSecretFromAnyVault(secretKey, fp, c.Strict)
		if errGet != nil {
			return NewError(fmt.Sprintf("access denied: secret '%s' not found or not accessible", secretKey), ExitAccessDenied)
		}

		// Check if we are returning an older value (only relevant in non-strict mode)
		if !c.Strict {
			latestSecret, _ := c.vaultResolver.GetSecretFromAnyVault(secretKey, nil)
			if latestSecret != nil && !latestSecret.AddedAt.Equal(secret.AddedAt) {
				_, _ = fmt.Fprintf(c.output.Stderr(), "warning: returning older value for '%s' (access to latest value is revoked)\n", secretKey)
			}
		}

		// Find the vault path for this secret
		idx := c.vaultResolver.FindSecretVaultIndex(secretKey)
		if idx >= 0 {
			entries := c.vaultResolver.GetConfig().Entries
			if idx < len(entries) {
				secretVaultPath = entries[idx].Path
			}
		}

		encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(secret.Value)
		if decodeErr != nil {
			return NewError(fmt.Sprintf("failed to decode encrypted value: %v", decodeErr), ExitGeneralError)
		}

		plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
		if decErr != nil {
			return NewError(fmt.Sprintf("failed to decrypt secret: %v", decErr), ExitGPGError)
		}
		decryptedValues = append(decryptedValues, string(plaintext))
	}

	if jsonOutput {
		encoder := json.NewEncoder(c.output.Stdout())
		encoder.SetIndent("", "  ")

		if all {
			if err := encoder.Encode(decryptedValuesWithTime); err != nil {
				return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
			}
		} else {
			output := SecretValueJSON{
				AddedAt: secret.AddedAt,
				Value:   decryptedValues[0],
				Vault:   secretVaultPath,
			}
			if err := encoder.Encode(output); err != nil {
				return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
			}
		}
	} else {
		if all {
			for _, item := range decryptedValuesWithTime {
				_, _ = fmt.Fprintf(c.output.Stdout(), "%s (%s): %s\n", item.AddedAt.Format(time.RFC3339), item.Vault, item.Value)
			}
		} else {
			if len(decryptedValues) > 0 {
				_, _ = fmt.Fprintf(c.output.Stdout(), "%s\n", decryptedValues[0])
			}
		}
	}

	return nil
}

// vaultGetFromIndex retrieves a secret from a specific vault index.
// If c.Strict is true (from config), only returns a value if the user has access to the LATEST value.
func (c *CLI) vaultGetFromIndex(key string, index int, all bool, jsonOutput bool, fp string) *Error {
	secretObj := c.vaultResolver.GetSecretByKeyFromVault(index, key)
	if secretObj == nil {
		return NewError(fmt.Sprintf("secret '%s' not found in vault", key), ExitVaultError)
	}

	if len(secretObj.Values) == 0 {
		return NewError(fmt.Sprintf("secret '%s' has no values", key), ExitVaultError)
	}

	entries := c.vaultResolver.GetConfig().Entries
	var vaultPath string
	if index < len(entries) {
		vaultPath = entries[index].Path
	}

	var decryptedValues []string
	var decryptedValuesWithTime []SecretValueJSON

	if all {
		// Decrypt all values in reverse order
		for i := len(secretObj.Values) - 1; i >= 0; i-- {
			val := secretObj.Values[i]

			hasAccess := false
			for _, authorizedFp := range val.AvailableTo {
				if authorizedFp == fp {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				continue
			}

			encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(val.Value)
			if decodeErr != nil {
				if c.Strict {
					return NewError(fmt.Sprintf("strict mode: failed to decode value from %s: %v", val.AddedAt, decodeErr), ExitGeneralError)
				}
				c.Warnf("failed to decode value from %s: %v", val.AddedAt, decodeErr)
				continue
			}

			plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
			if decErr != nil {
				if c.Strict {
					return NewError(fmt.Sprintf("strict mode: failed to decrypt value from %s: %v", val.AddedAt, decErr), ExitGPGError)
				}
				c.Warnf("failed to decrypt value from %s: %v", val.AddedAt, decErr)
				continue
			}
			valStr := string(plaintext)
			decryptedValues = append(decryptedValues, valStr)
			decryptedValuesWithTime = append(decryptedValuesWithTime, SecretValueJSON{
				AddedAt: val.AddedAt,
				Value:   valStr,
				Vault:   vaultPath,
			})
		}
	} else {
		// Use manager to get accessible value (supporting fallback)
		manager := c.vaultResolver.GetVaultManager(index)
		if manager == nil {
			cfg := c.vaultResolver.GetConfig()
			path := "unknown"
			if index >= 0 && index < len(cfg.Entries) {
				path = cfg.Entries[index].Path
			}
			return NewError(fmt.Sprintf("Vault %d (%s): not found", index+1, path), ExitVaultError)
		}

		val := manager.GetAccessibleSecretValue(fp, key, c.Strict)
		if val == nil {
			return NewError(fmt.Sprintf("access denied: you do not have access to secret '%s'", key), ExitAccessDenied)
		}

		// Check if we are returning an older value (only relevant in non-strict mode)
		if !c.Strict {
			latestVal := secretObj.Values[len(secretObj.Values)-1]
			if !val.AddedAt.Equal(latestVal.AddedAt) {
				_, _ = fmt.Fprintf(c.output.Stderr(), "warning: returning older value for '%s' (access to latest value is revoked)\n", key)
			}
		}

		encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(val.Value)
		if decodeErr != nil {
			return NewError(fmt.Sprintf("failed to decode encrypted value: %v", decodeErr), ExitGeneralError)
		}

		plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
		if decErr != nil {
			return NewError(fmt.Sprintf("failed to decrypt secret: %v", decErr), ExitGPGError)
		}
		decryptedValues = append(decryptedValues, string(plaintext))
		decryptedValuesWithTime = append(decryptedValuesWithTime, SecretValueJSON{
			AddedAt: val.AddedAt,
			Value:   string(plaintext),
			Vault:   vaultPath,
		})
	}

	if len(decryptedValues) == 0 {
		return NewError(fmt.Sprintf("no accessible values for secret '%s'", key), ExitAccessDenied)
	}

	if jsonOutput {
		encoder := json.NewEncoder(c.output.Stdout())
		encoder.SetIndent("", "  ")

		if all {
			if err := encoder.Encode(decryptedValuesWithTime); err != nil {
				return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
			}
		} else {
			if err := encoder.Encode(decryptedValuesWithTime[0]); err != nil {
				return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
			}
		}
	} else {
		if all {
			for _, item := range decryptedValuesWithTime {
				_, _ = fmt.Fprintf(c.output.Stdout(), "%s (%s): %s\n", item.AddedAt.Format(time.RFC3339), item.Vault, item.Value)
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "%s\n", decryptedValues[0])
		}
	}

	return nil
}

// vaultGetLastFromAllVaults retrieves the most recent value (by added_at) across all vaults
func (c *CLI) vaultGetLastFromAllVaults(key string, jsonOutput bool, fp string) *Error {
	var mostRecentValue *vault.SecretValue
	var mostRecentTime time.Time
	var mostRecentVaultPath string

	entries := c.vaultResolver.GetConfig().Entries

	for i, entry := range entries {
		secretObj := c.vaultResolver.GetSecretByKeyFromVault(i, key)
		if secretObj == nil || len(secretObj.Values) == 0 {
			continue
		}

		for j := range secretObj.Values {
			val := &secretObj.Values[j]

			hasAccess := false
			for _, authorizedFp := range val.AvailableTo {
				if authorizedFp == fp {
					hasAccess = true
					break
				}
			}
			if !hasAccess {
				continue
			}

			if mostRecentValue == nil || val.AddedAt.After(mostRecentTime) {
				mostRecentValue = val
				mostRecentTime = val.AddedAt
				mostRecentVaultPath = entry.Path
			}
		}
	}

	if mostRecentValue == nil {
		return NewError(fmt.Sprintf("secret '%s' not found in any vault", key), ExitVaultError)
	}

	encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(mostRecentValue.Value)
	if decodeErr != nil {
		return NewError(fmt.Sprintf("failed to decode encrypted value: %v", decodeErr), ExitGeneralError)
	}

	plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
	if decErr != nil {
		return NewError(fmt.Sprintf("failed to decrypt secret: %v", decErr), ExitGPGError)
	}

	if jsonOutput {
		encoder := json.NewEncoder(c.output.Stdout())
		encoder.SetIndent("", "  ")
		output := SecretValueJSON{
			AddedAt: mostRecentValue.AddedAt,
			Value:   string(plaintext),
			Vault:   mostRecentVaultPath,
		}
		if err := encoder.Encode(output); err != nil {
			return NewError(fmt.Sprintf("failed to encode json: %v", err), ExitGeneralError)
		}
	} else {
		_, _ = fmt.Fprintf(c.output.Stdout(), "%s\n", string(plaintext))
	}

	return nil
}

// readSecretFromStdin reads a secret from stdin
func (c *CLI) readSecretFromStdin() (string, error) {
	scanner := bufio.NewScanner(c.stdin)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no input provided")
}
