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

// SecretRevoke re-encrypts a secret without the specified fingerprint, effectively revoking their access.
// If the secret is shared with the fingerprint, it re-encrypts with every other public key except
// the one corresponding to the fingerprint, updates available_to, regenerates the hash, and signs it.
func (c *CLI) SecretRevoke(secretKey, targetFingerprint string, vaultIndex int) *Error {
	// Validate secret key format
	if _, err := vault.NormalizeSecretKey(secretKey); err != nil {
		return NewError(vault.FormatSecretKeyError(err), ExitValidationError)
	}

	// If vaultIndex < 0, find the vault that has the secret
	if vaultIndex < 0 {
		vaultIndex = c.vaultResolver.FindSecretVaultIndex(secretKey)
		if vaultIndex < 0 {
			return NewError(fmt.Sprintf("secret not found in any vault: %s", secretKey), ExitVaultError)
		}
	}

	return c.secretRevokeInVault(secretKey, targetFingerprint, vaultIndex, false)
}

// SecretRevokeAll revokes access to a secret from a fingerprint across all vaults.
func (c *CLI) SecretRevokeAll(secretKey, targetFingerprint string) *Error {
	// Validate secret key format
	if _, err := vault.NormalizeSecretKey(secretKey); err != nil {
		return NewError(vault.FormatSecretKeyError(err), ExitValidationError)
	}

	vaultCount := c.vaultResolver.VaultCount()
	if vaultCount == 0 {
		return NewError("no vaults configured", ExitVaultError)
	}

	// Get target identity info for header
	targetIdentity := c.vaultResolver.GetIdentityByFingerprint(targetFingerprint)
	targetUID := targetFingerprint
	if targetIdentity != nil {
		targetUID = targetIdentity.UID
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Revoking access to secret '%s' from: %s %s\n", secretKey, targetUID, targetFingerprint)

	vaultPaths := c.vaultResolver.GetVaultPaths()
	revokedCount := 0
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

		// Check if secret has values and is shared with target
		if len(secretObj.Values) == 0 {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, empty secret\n", displayPos, vaultPath)
			skippedCount++
			continue
		}
		currentValue := secretObj.Values[len(secretObj.Values)-1]
		if !slices.Contains(currentValue.AvailableTo, targetFingerprint) {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, target does not have access\n", displayPos, vaultPath)
			skippedCount++
			continue
		}

		err := c.secretRevokeInVault(secretKey, targetFingerprint, i, true)
		if err != nil {
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, %s\n", displayPos, vaultPath, err.Message)
			failureCount++
			continue
		}
		_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): revoked access to secret '%s' for %s\n", displayPos, vaultPath, secretKey, targetFingerprint)
		revokedCount++
	}

	if revokedCount == 0 && failureCount > 0 && skippedCount == 0 {
		return NewError("failed to revoke secret in any vault", ExitVaultError)
	}
	return nil
}

// secretRevokeInVault performs the revocation logic for a specific vault
func (c *CLI) secretRevokeInVault(secretKey, targetFingerprint string, vaultIndex int, silent bool) *Error {
	fp, err := c.checkFingerprintRequired("secret revoke")
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
		}
		return nil
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

	// Ensure the current user has access to the latest value (prevent revocation by users with only old access)
	if !slices.Contains(currentValue.AvailableTo, fp) {
		return NewError(fmt.Sprintf("access denied: you do not have access to the latest value of secret: %s", secretKey), ExitAccessDenied)
	}

	// Check if the secret is shared with the target fingerprint
	if !slices.Contains(currentValue.AvailableTo, targetFingerprint) {
		if !silent {
			vaultPath := ""
			vaultPaths := c.vaultResolver.GetVaultPaths()
			if vaultIndex >= 0 && vaultIndex < len(vaultPaths) {
				vaultPath = vaultPaths[vaultIndex]
			}
			displayPos := vaultIndex + 1
			_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): skipped, target does not have access\n", displayPos, vaultPath)
			return nil
		}
		return NewError("target does not have access", ExitGeneralError)
	}

	// Warn if the logged-in user is revoking their own access
	if fp == targetFingerprint && !silent {
		_, _ = fmt.Fprintf(c.output.Stderr(), "warning: you have revoked your own access to secret '%s'\n", secretKey)
	}

	// Warn if the fingerprint is not defined in the vault (always proceed with revocation)
	targetIdentity := c.vaultResolver.GetIdentityByFingerprint(targetFingerprint)
	if targetIdentity == nil && !silent {
		_, _ = fmt.Fprintf(c.output.Stderr(), "warning: expected identity %s to exist in vault, but was not found\n", targetFingerprint)
	}

	// Cannot revoke from self if you're the only one with access
	newRecipients := make([]string, 0, len(currentValue.AvailableTo)-1)
	for _, recipientFP := range currentValue.AvailableTo {
		if recipientFP != targetFingerprint {
			newRecipients = append(newRecipients, recipientFP)
		}
	}

	if len(newRecipients) == 0 {
		return NewError("cannot revoke: this would remove all access to the secret", ExitGeneralError)
	}

	// Decrypt the current value
	encryptedArmored, decodeErr := base64.StdEncoding.DecodeString(currentValue.Value)
	if decodeErr != nil {
		return NewError(fmt.Sprintf("failed to decode encrypted value: %v", decodeErr), ExitGeneralError)
	}

	plaintext, decErr := c.gpgClient.DecryptWithAgent(encryptedArmored, fp)
	if decErr != nil {
		return NewError(fmt.Sprintf("failed to decrypt secret: %v", decErr), ExitGPGError)
	}

	sort.Strings(newRecipients)

	// Gather public keys for the remaining recipients
	var recipientPublicKeys []string
	for _, recipientFP := range newRecipients {
		recipientIdentity := c.vaultResolver.GetIdentityByFingerprint(recipientFP)
		if recipientIdentity == nil {
			return NewError(fmt.Sprintf("recipient identity not found: %s", recipientFP), ExitVaultError)
		}
		recipientPublicKeys = append(recipientPublicKeys, recipientIdentity.PublicKey)
	}

	// Re-encrypt for the remaining recipients
	encryptedArmoredNew, encErr := c.gpgClient.EncryptToRecipients(plaintext, recipientPublicKeys, nil)
	if encErr != nil {
		return NewError(fmt.Sprintf("failed to encrypt secret: %v", encErr), ExitGeneralError)
	}

	encryptedBase64 := base64.StdEncoding.EncodeToString([]byte(encryptedArmoredNew))

	// Create the new secret value with updated metadata
	now := time.Now().UTC()
	availableTo := strings.Join(newRecipients, ",")
	valueMetadata := fmt.Sprintf("value:%s:%s:%s:%s:%s:%t", now.Format(time.RFC3339Nano), secretKey, availableTo, fp, encryptedBase64, false)
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
		return NewError(fmt.Sprintf("failed to add revoked value: %v", addErr), ExitVaultError)
	}

	if !silent {
		vaultPath := ""
		vaultPaths := c.vaultResolver.GetVaultPaths()
		if vaultIndex >= 0 && vaultIndex < len(vaultPaths) {
			vaultPath = vaultPaths[vaultIndex]
		}
		displayPos := vaultIndex + 1
		_, _ = fmt.Fprintf(c.output.Stdout(), "Vault %d (%s): revoked access to secret '%s' for %s\n", displayPos, vaultPath, secretKey, targetFingerprint)
	}
	return nil
}
