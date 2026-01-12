package cli

import (
	"fmt"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// ensureIdentityInVault ensures the identity exists in the specified vault index
// If the identity doesn't exist, it will be auto-added with a warning
func (c *CLI) ensureIdentityInVault(fingerprint string, index int) *Error {
	if c.vaultResolver.IdentityExistsInVault(fingerprint, index) {
		return nil
	}

	// Always auto-add with warning (simplified behavior - no strict mode check)
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
		SignedBy:      fingerprint,
	}

	newIdentity.Hash = identity.ComputeIdentityHash(&newIdentity)

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
