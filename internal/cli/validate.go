package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/crypto"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// Validate validates the configuration and vault files
func (c *CLI) Validate(fix bool) *Error {
	_, _ = fmt.Fprintf(c.output.Stdout(), "=== DotSecEnv Configuration Validation ===\n\n")

	absConfigPath, err := filepath.Abs(c.configPath)
	if err != nil {
		absConfigPath = c.configPath
	}
	_, _ = fmt.Fprintf(c.output.Stdout(), "Configuration file: %s\n", absConfigPath)
	if _, err := os.Stat(absConfigPath); err != nil {
		return NewError(fmt.Sprintf("config file not found: %s", absConfigPath), ExitConfigError)
	}
	_, _ = fmt.Fprintf(c.output.Stdout(), "  Status: ✓ Found\n\n")

	_, _ = fmt.Fprintf(c.output.Stdout(), "Approved Algorithms:\n")
	if len(c.config.ApprovedAlgorithms) == 0 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "  (No requirements defined)\n")
	} else {
		for _, req := range c.config.ApprovedAlgorithms {
			_, _ = fmt.Fprintf(c.output.Stdout(), "  %s: minimum %d bits", req.Algo, req.MinBits)
			if len(req.Curves) > 0 {
				_, _ = fmt.Fprintf(c.output.Stdout(), " (curves: %s)", strings.Join(req.Curves, ", "))
			}
			_, _ = fmt.Fprintf(c.output.Stdout(), " ✓\n")
		}
	}
	_, _ = fmt.Fprintf(c.output.Stdout(), "\n")

	_, _ = fmt.Fprintf(c.output.Stdout(), "Vault Configuration:\n")
	vaultCount := 0
	hasErrors := false

	for i, entry := range c.vaultResolver.GetConfig().Entries {
		vaultCount++
		vaultPath := entry.Path

		absVaultPath, err := filepath.Abs(vaultPath)
		if err != nil {
			absVaultPath = vaultPath
		}

		_, _ = fmt.Fprintf(c.output.Stdout(), "  Vault %d: %s\n", vaultCount, absVaultPath)

		fileInfo, err := os.Stat(absVaultPath)
		if err != nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Status: ⚠ File not found (warning)\n")
			continue
		}

		if fileInfo.Size() == 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Status: ✗ Vault file is empty (invalid vault structure)\n")
			hasErrors = true
			continue
		}

		manager := c.vaultResolver.GetVaultManager(i)
		if manager == nil {
			loadErr := c.vaultResolver.GetLoadError(i)
			errMsg := "unknown error"
			if loadErr != nil {
				errMsg = loadErr.Error()
			}
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Status: ✗ Failed to load: %s\n", errMsg)
			hasErrors = true
			continue
		}

		vaultData := manager.Get()

		_, _ = fmt.Fprintf(c.output.Stdout(), "    Status: ✓ Valid vault file\n")
		_, _ = fmt.Fprintf(c.output.Stdout(), "    Identities: %d\n", len(vaultData.Identities))
		_, _ = fmt.Fprintf(c.output.Stdout(), "    Secrets: %d\n", len(vaultData.Secrets))

		_, _ = fmt.Fprintf(c.output.Stdout(), "\n    === Structural Validation ===\n")

		structErrors := validateYAMLStructure(absVaultPath)
		if len(structErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    YAML Indentation: ✗ (%d issues)\n", len(structErrors))
			for _, err := range structErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    YAML Indentation: ✓\n")
		}

		orderErrors := validateYAMLFieldOrder(absVaultPath)
		if len(orderErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Field Order: ✗ (%d issues)\n", len(orderErrors))
			for _, err := range orderErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Field Order: ✓\n")
		}

		dataErrors := validateVaultData(vaultData, manager)
		if len(dataErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Vault Structure: ✗ (%d issues)\n", len(dataErrors))
			for _, err := range dataErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Vault Structure: ✓\n")
		}

		encErrors := validateSecretEncryption(vaultData)
		if len(encErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Secret Encryption: ✗ (%d issues)\n", len(encErrors))
			for _, err := range encErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Secret Encryption: ✓\n")
		}

		metaErrors := validateSecretMetadata(vaultData)
		if len(metaErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Secret Metadata: ✗ (%d issues)\n", len(metaErrors))
			for _, err := range metaErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Secret Metadata: ✓\n")
		}

		headerErrors := validateHeaderLineNumbers(manager.GetHeader())
		if len(headerErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Header Line Numbers: ✗ (%d issues)\n", len(headerErrors))
			for _, err := range headerErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Header Line Numbers: ✓\n")
		}

		fileStructErrors := validateVaultFileStructure(manager.GetHeader(), manager.GetLines())
		if len(fileStructErrors) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    File Structure: ✗ (%d issues)\n", len(fileStructErrors))
			for _, err := range fileStructErrors {
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s at %s\n", err.Message, err.Path)
				hasErrors = true
			}
		} else {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    File Structure: ✓\n")
		}

		_, _ = fmt.Fprintf(c.output.Stdout(), "\n    === Identity Validation ===\n")

		if len(vaultData.Identities) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Identity Details:\n")
			for _, identity := range vaultData.Identities {
				keyInfo, err := c.gpgClient.GetPublicKeyInfo(identity.Fingerprint)
				var algo string
				var bits int
				if err != nil {
					if identity.Curve != "" {
						algo = identity.Algorithm + " " + identity.Curve
					} else {
						algo = identity.Algorithm
					}
					// bits removed (see previous fix)
				} else {
					algo = keyInfo.Algorithm
					// bits removed (see previous fix)
				}

				name, bits := crypto.GetAlgorithmDetails(algo)
				if bits > 0 {
					_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s (%s %d bits)", identity.UID, name, bits)
				} else {
					_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s (%s)", identity.UID, name)
				}

				if c.config.IsAlgorithmAllowed(algo, bits) {
					_, _ = fmt.Fprintf(c.output.Stdout(), " ✓\n")
				} else {
					_, _ = fmt.Fprintf(c.output.Stdout(), " ✗ (not allowed by requirements)\n")
					return NewError(fmt.Sprintf("algorithm not allowed: %s", algo), ExitAlgorithmNotAllowed)
				}
			}
		}

		_, _ = fmt.Fprintf(c.output.Stdout(), "\n    === Secret Validation ===\n")

		if len(vaultData.Secrets) > 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "    Secret Details:\n")
			secretKeys := make([]string, 0, len(vaultData.Secrets))
			secretMap := make(map[string]*vault.Secret)
			for i := range vaultData.Secrets {
				key := vaultData.Secrets[i].Key
				secretKeys = append(secretKeys, key)
				secretMap[key] = &vaultData.Secrets[i]
			}
			sort.Strings(secretKeys)

			for _, key := range secretKeys {
				secret := secretMap[key]
				_, _ = fmt.Fprintf(c.output.Stdout(), "      - %s: %d value(s)", secret.Key, len(secret.Values))

				if secret.Signature == "" {
					_, _ = fmt.Fprintf(c.output.Stdout(), " ✗ (missing signature)")
					hasErrors = true
				} else {
					_, _ = fmt.Fprintf(c.output.Stdout(), " ✓")
				}
				_, _ = fmt.Fprintf(c.output.Stdout(), "\n")

				for j, value := range secret.Values {
					if value.Signature == "" {
						_, _ = fmt.Fprintf(c.output.Stdout(), "        [%d] ✗ Missing signature\n", j+1)
						hasErrors = true
					} else {
						_, _ = fmt.Fprintf(c.output.Stdout(), "        [%d] added at %s ✓\n", j+1, value.AddedAt.Format("2006-01-02 15:04:05"))
					}
				}
			}
		}
		_, _ = fmt.Fprintf(c.output.Stdout(), "\n")
	}

	if vaultCount == 0 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "  (No vaults configured)\n\n")
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "=== Validation Complete ===\n")
	if hasErrors {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Status: ✗ Validation failed - see errors above\n")
		return NewError("validation failed", ExitVaultError)
	}
	_, _ = fmt.Fprintf(c.output.Stdout(), "Status: ✓ All checks passed\n")

	return nil
}
