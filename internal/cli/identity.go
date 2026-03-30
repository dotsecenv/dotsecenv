package cli

import (
	"fmt"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// IdentityAdd adds a GPG identity to one or more vaults.
// If addAll is true, the identity is added to every configured vault.
// If vaultPath is non-empty, only the vault at that path is targeted.
// If fromIndex > 0, the vault at that 1-based index is targeted.
// When none of the above are set and exactly one vault is configured, it is auto-selected.
func (c *CLI) IdentityAdd(fingerprint string, addAll bool, vaultPath string, fromIndex int) *Error {
	// The current user signs the new identity entry (vouching for it)
	signerFP, fpErr := c.checkFingerprintRequired("identity add")
	if fpErr != nil {
		return fpErr
	}

	config := c.vaultResolver.GetConfig()
	entries := config.Entries

	// Determine which vault indices to target
	var indices []int
	switch {
	case addAll:
		for i := range entries {
			indices = append(indices, i)
		}
		if len(indices) == 0 {
			return NewError("no vaults configured", ExitConfigError)
		}
	default:
		// Single vault: use the shared resolver (handles -v path, -v index,
		// auto-select for single vault, and interactive prompt for multiple)
		idx, err := c.resolveWritableVaultIndex(vaultPath, fromIndex, "Select vault to add identity to:")
		if err != nil {
			return err
		}
		indices = []int{idx}
	}

	var added, skipped, failed int
	var lastErr *Error
	for _, idx := range indices {
		vPath := entries[idx].Path

		if c.vaultResolver.IdentityExistsInVault(fingerprint, idx) {
			_, _ = fmt.Fprintf(c.output.Stderr(), "skipped: identity %s already in vault %d (%s)\n", fingerprint, idx+1, vPath)
			skipped++
			continue
		}

		if err := c.addIdentityToVault(fingerprint, signerFP, idx); err != nil {
			_, _ = fmt.Fprintf(c.output.Stderr(), "failed: vault %d (%s): %s\n", idx+1, vPath, err.Message)
			lastErr = err
			failed++
			continue
		}

		_, _ = fmt.Fprintf(c.output.Stdout(), "added: identity %s to vault %d (%s)\n", fingerprint, idx+1, vPath)
		added++
	}

	if len(indices) > 1 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "\nsummary: added=%d skipped=%d failed=%d\n", added, skipped, failed)
	}

	if failed > 0 {
		// When a single vault was targeted, return its specific error
		if len(indices) == 1 && lastErr != nil {
			return lastErr
		}
		return NewError(fmt.Sprintf("%d vault(s) failed", failed), ExitVaultError)
	}
	return nil
}

// addIdentityToVault builds, signs, and adds an identity to the vault at the given index.
// signerFingerprint is the current user's key used to sign (vouch for) the new identity.
func (c *CLI) addIdentityToVault(fingerprint string, signerFingerprint string, index int) *Error {
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
		SignedBy:      signerFingerprint,
	}

	newIdentity.Hash = identity.ComputeIdentityHash(&newIdentity)

	signature, signErr := c.gpgClient.SignDataWithAgent(signerFingerprint, []byte(newIdentity.Hash))
	if signErr != nil {
		return NewError(fmt.Sprintf("failed to sign identity: %v", signErr), ExitGPGError)
	}
	newIdentity.Signature = signature

	if err := c.vaultResolver.AddIdentity(newIdentity, index); err != nil {
		return NewError(fmt.Sprintf("failed to add identity: %v", err), ExitVaultError)
	}

	if err := c.vaultResolver.SaveVault(index); err != nil {
		return NewError(fmt.Sprintf("failed to save vault: %v", err), ExitVaultError)
	}

	return nil
}

// ensureIdentityInVault ensures the identity exists in the specified vault index.
// If the identity doesn't exist, it will be auto-added with a warning.
// The current user's key is used to sign (vouch for) the new identity.
func (c *CLI) ensureIdentityInVault(fingerprint string, index int) *Error {
	if c.vaultResolver.IdentityExistsInVault(fingerprint, index) {
		return nil
	}

	signerFP, fpErr := c.checkFingerprintRequired("identity auto-add")
	if fpErr != nil {
		return fpErr
	}

	// Auto-add with warning
	vaultPath := c.vaultResolver.GetConfig().Entries[index].Path
	_, _ = fmt.Fprintf(c.output.Stderr(), "warning: identity %s did not previously exist in vault\n", fingerprint)
	_, _ = fmt.Fprintf(c.output.Stderr(), "warning: adding identity to vault %d (%s)\n", index+1, vaultPath)
	_, _ = fmt.Fprintf(c.output.Stderr(), "warning: you can inspect the vault with 'dotsecenv vault describe'\n")

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
		SignedBy:      signerFP,
	}

	newIdentity.Hash = identity.ComputeIdentityHash(&newIdentity)

	signature, signErr := c.gpgClient.SignDataWithAgent(signerFP, []byte(newIdentity.Hash))
	if signErr != nil {
		return NewError(fmt.Sprintf("failed to sign identity: %v", signErr), ExitGPGError)
	}
	newIdentity.Signature = signature

	if err := c.vaultResolver.AddIdentity(newIdentity, index); err != nil {
		return NewError(fmt.Sprintf("failed to add identity: %v", err), ExitVaultError)
	}

	return nil
}
