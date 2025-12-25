package cli

import (
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// SecretShare shares a secret with another identity
func (c *CLI) SecretShare(secretKeyArg, targetFingerprint string, vaultIndex int) *Error {
	// Normalize secret key for lookup (validation errors are non-fatal to support legacy keys)
	secretKey := secretKeyArg
	if normalized, normErr := vault.NormalizeSecretKey(secretKeyArg); normErr == nil {
		secretKey = normalized
	}

	// If vaultIndex < 0, find the vault that has the secret
	if vaultIndex < 0 {
		vaultIndex = c.vaultResolver.FindSecretVaultIndex(secretKey)
		if vaultIndex < 0 {
			return NewError(fmt.Sprintf("secret not found: %s", secretKey), ExitVaultError)
		}
	}

	return c.secretShareInVault(secretKey, targetFingerprint, vaultIndex, false)
}

// SecretShareAll shares a secret with a fingerprint across all vaults where the secret exists.
func (c *CLI) SecretShareAll(secretKeyArg, targetFingerprint string) *Error {
	// Normalize secret key for lookup (validation errors are non-fatal to support legacy keys)
	secretKey := secretKeyArg
	if normalized, normErr := vault.NormalizeSecretKey(secretKeyArg); normErr == nil {
		secretKey = normalized
	}

	vaultCount := c.vaultResolver.VaultCount()
	if vaultCount == 0 {
		return NewError("no vaults configured", ExitVaultError)
	}

	// Get target identity info for header
	targetIdentity := c.vaultResolver.GetIdentityByFingerprint(targetFingerprint)
	if targetIdentity == nil {
		return NewError(fmt.Sprintf("identity not found: %s", targetFingerprint), ExitVaultError)
	}

	// Print header
	_, _ = fmt.Fprintf(c.output.Stdout(), "Sharing secret '%s' with: %s %s\n", secretKey, targetIdentity.UID, targetFingerprint)

	vaultPaths := c.vaultResolver.GetVaultPaths()
	sharedCount := 0
	skippedCount := 0
	failureCount := 0

	for i := 0; i < vaultCount; i++ {
		displayPos := i + 1
		vaultPath := ""
		if i < len(vaultPaths) {
			vaultPath = vaultPaths[i]
		}

		secretObj := c.vaultResolver.GetSecretByKeyFromVault(i, secretKey)
		if secretObj == nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, secret not found in vault\n", displayPos, vaultPath)
			skippedCount++
			continue
		}

		// Check if already shared
		if len(secretObj.Values) > 0 {
			currentValue := secretObj.Values[len(secretObj.Values)-1]
			if slices.Contains(currentValue.AvailableTo, targetFingerprint) {
				_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, already shared\n", displayPos, vaultPath)
				skippedCount++
				continue
			}
		}

		// Use the existing SecretShare logic but for a specific vault (silent mode)
		err := c.secretShareInVault(secretKey, targetFingerprint, i, true)
		if err != nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, %s\n", displayPos, vaultPath, err.Message)
			failureCount++
			continue
		}
		_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): shared secret '%s' with %s\n", displayPos, vaultPath, secretKey, targetFingerprint)
		sharedCount++
	}

	if sharedCount == 0 && failureCount > 0 && skippedCount == 0 {
		return NewError("failed to share secret in any vault", ExitVaultError)
	}
	return nil
}

// secretShareInVault shares a secret with a fingerprint in a specific vault.
func (c *CLI) secretShareInVault(secretKey, targetFingerprint string, vaultIndex int, silent bool) *Error {
	fp, err := c.checkFingerprintRequired("secret share")
	if err != nil {
		return err
	}

	secretObj := c.vaultResolver.GetSecretByKeyFromVault(vaultIndex, secretKey)
	if secretObj == nil {
		if !silent {
			vaultPath := ""
			vaultPaths := c.vaultResolver.GetVaultPaths()
			if vaultIndex >= 0 && vaultIndex < len(vaultPaths) {
				vaultPath = vaultPaths[vaultIndex]
			}
			displayPos := vaultIndex + 1
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, secret not found in vault\n", displayPos, vaultPath)
			return nil
		}
		return NewError(fmt.Sprintf("secret not found in vault: %s", secretKey), ExitVaultError)
	}

	manager := c.vaultResolver.GetVaultManager(vaultIndex)
	if manager == nil || !manager.CanIdentityAccessSecret(fp, secretKey) {
		return NewError(fmt.Sprintf("access denied: you do not have access to secret: %s", secretKey), ExitAccessDenied)
	}

	// Get the most recent value
	if len(secretObj.Values) == 0 {
		return NewError(fmt.Sprintf("secret has no values: %s", secretKey), ExitVaultError)
	}
	currentValue := secretObj.Values[len(secretObj.Values)-1]

	// Check if already shared
	if slices.Contains(currentValue.AvailableTo, targetFingerprint) {
		if !silent {
			vaultPath := ""
			vaultPaths := c.vaultResolver.GetVaultPaths()
			if vaultIndex >= 0 && vaultIndex < len(vaultPaths) {
				vaultPath = vaultPaths[vaultIndex]
			}
			displayPos := vaultIndex + 1
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, already shared\n", displayPos, vaultPath)
		}
		return nil
	}

	targetIdentity := c.vaultResolver.GetIdentityByFingerprint(targetFingerprint)
	if targetIdentity == nil {
		return NewError(fmt.Sprintf("identity not found: %s", targetFingerprint), ExitVaultError)
	}

	encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(currentValue.Value)
	if decodeErr != nil {
		return NewError(fmt.Sprintf("failed to decode encrypted value: %v", decodeErr), ExitGeneralError)
	}

	plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
	if decErr != nil {
		return NewError(fmt.Sprintf("failed to decrypt secret: %v", decErr), ExitGPGError)
	}

	currentRecipients := currentValue.AvailableTo
	newRecipients := make([]string, len(currentRecipients))
	copy(newRecipients, currentRecipients)
	newRecipients = append(newRecipients, targetFingerprint)

	sort.Strings(newRecipients)

	var recipientPublicKeys []string
	for _, recipientFP := range newRecipients {
		recipientIdentity := c.vaultResolver.GetIdentityByFingerprint(recipientFP)
		if recipientIdentity == nil {
			return NewError(fmt.Sprintf("recipient identity not found: %s", recipientFP), ExitVaultError)
		}
		recipientPublicKeys = append(recipientPublicKeys, recipientIdentity.PublicKey)
	}

	encryptedArmoredNew, encErr := c.gpgClient.EncryptToRecipients(plaintext, recipientPublicKeys, nil)
	if encErr != nil {
		return NewError(fmt.Sprintf("failed to encrypt secret: %v", encErr), ExitGeneralError)
	}

	encryptedBase64 := base64.StdEncoding.EncodeToString([]byte(encryptedArmoredNew))

	now := time.Now().UTC()
	availableTo := strings.Join(newRecipients, ",")
	valueMetadata := fmt.Sprintf("value:%s:%s:%s:%s:%s", now.Format(time.RFC3339Nano), secretKey, availableTo, fp, encryptedBase64)
	algorithmBits := 256
	signingIdentity := c.vaultResolver.GetIdentityByFingerprint(fp)
	if signingIdentity != nil {
		algorithmBits = signingIdentity.AlgorithmBits
	}
	valueHash := ComputeHash([]byte(valueMetadata), algorithmBits)
	valueSig, sigErr := c.gpgClient.SignDataWithAgent(fp, []byte(valueHash))
	if sigErr != nil {
		return NewError(fmt.Sprintf("failed to sign secret value: %v", sigErr), ExitGeneralError)
	}

	newSecretValue := vault.SecretValue{
		AddedAt:     now,
		AvailableTo: newRecipients,
		Hash:        valueHash,
		Signature:   valueSig,
		SignedBy:    fp,
		Value:       encryptedBase64,
	}

	// Use AddSecret which handles adding values to existing secrets via the writer
	newSecret := vault.Secret{
		Key:    secretKey,
		Values: []vault.SecretValue{newSecretValue},
	}
	if addErr := c.vaultResolver.AddSecret(newSecret, vaultIndex); addErr != nil {
		return NewError(fmt.Sprintf("failed to add shared value: %v", addErr), ExitVaultError)
	}

	if !silent {
		vaultPath := ""
		vaultPaths := c.vaultResolver.GetVaultPaths()
		if vaultIndex >= 0 && vaultIndex < len(vaultPaths) {
			vaultPath = vaultPaths[vaultIndex]
		}
		displayPos := vaultIndex + 1
		_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): shared secret '%s' with %s\n", displayPos, vaultPath, secretKey, targetFingerprint)
	}
	return nil
}
