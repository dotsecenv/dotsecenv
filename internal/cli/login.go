package cli

import (
	"fmt"
	"os"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
)

// Login initializes the user's identity in the vault
func (c *CLI) Login(fingerprint string) *Error {
	envFP := os.Getenv("DOTSECENV_FINGERPRINT")
	if envFP != "" && c.config.Fingerprint != "" && c.config.Fingerprint != fingerprint {
		c.Warnf("DOTSECENV_FINGERPRINT is set; new fingerprint will be cached but not used in this session")
	}

	publicKeyInfo, pubKeyErr := c.gpgClient.GetPublicKeyInfo(fingerprint)
	if pubKeyErr != nil {
		return NewError(fmt.Sprintf("failed to get public key for fingerprint '%s': %v\nMake sure your GPG key is available in gpg-agent", fingerprint, pubKeyErr), ExitGPGError)
	}

	if publicKeyInfo.AlgorithmBits > 0 {
		_, _ = fmt.Fprintf(c.output.Stderr(), "logged in with identity: %s (%s %d-bit) %s\n", publicKeyInfo.UID, publicKeyInfo.Algorithm, publicKeyInfo.AlgorithmBits, fingerprint)
	} else {
		_, _ = fmt.Fprintf(c.output.Stderr(), "logged in with identity: %s (%s) %s\n", publicKeyInfo.UID, publicKeyInfo.Algorithm, fingerprint)
	}

	// The algorithm and encryption capability checks are now handled by createSignedIdentity
	// but we still need to save the config fingerprint before potentially returning an error
	// from createSignedIdentity if the identity is new.
	// However, the original logic saved config.Fingerprint *before* the identity creation.
	// Let's keep that order.
	c.config.Fingerprint = fingerprint
	if err := config.Save(c.configPath, c.config); err != nil {
		return NewError(fmt.Sprintf("failed to save config: %v", err), ExitConfigError)
	}

	return nil
}
