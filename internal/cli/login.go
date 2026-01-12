package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
)

// createSignedLogin creates a Login struct with cryptographic proof.
// This function is used by both the `login` command and `init config --login`.
func createSignedLogin(gpgClient gpg.Client, fingerprint string) (*config.Login, error) {
	addedAt := time.Now().UTC()

	// Create canonical string for hashing: login:{added_at_rfc3339}:{fingerprint}
	canonical := fmt.Sprintf("login:%s:%s", addedAt.Format(time.RFC3339), fingerprint)

	// Compute SHA-256 hash
	hashBytes := sha256.Sum256([]byte(canonical))
	hashHex := hex.EncodeToString(hashBytes[:])

	// Sign the hash with GPG
	signature, signErr := gpgClient.SignDataWithAgent(fingerprint, hashBytes[:])
	if signErr != nil {
		return nil, fmt.Errorf("failed to sign login proof: %w", signErr)
	}

	return &config.Login{
		Fingerprint: fingerprint,
		AddedAt:     addedAt,
		Hash:        hashHex,
		Signature:   signature,
	}, nil
}

// CreateSignedLogin is the exported version for use by init.go
func CreateSignedLogin(gpgClient gpg.Client, fingerprint string) (*config.Login, error) {
	return createSignedLogin(gpgClient, fingerprint)
}

// selectSecretKey lists available secret keys and prompts the user to select one.
func (c *CLI) selectSecretKey() (string, *Error) {
	keys, err := c.gpgClient.ListSecretKeys()
	if err != nil {
		return "", NewError(fmt.Sprintf("failed to list secret keys: %v", err), ExitGPGError)
	}

	if len(keys) == 0 {
		return "", NewError("no secret keys found in GPG keyring.\nCreate a GPG key first with: dotsecenv identity create", ExitGPGError)
	}

	// If only one key, auto-select it
	if len(keys) == 1 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Auto-selecting the only available key: %s (%s)\n", keys[0].UID, keys[0].Fingerprint[:16]+"...")
		return keys[0].Fingerprint, nil
	}

	// Build display options for interactive selection
	var options []string
	for _, key := range keys {
		// Show first 16 chars of fingerprint for readability
		shortFP := key.Fingerprint
		if len(shortFP) > 16 {
			shortFP = shortFP[:16] + "..."
		}
		options = append(options, fmt.Sprintf("%s (%s)", key.UID, shortFP))
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Available secret keys:\n")
	_, _ = fmt.Fprintf(c.output.Stdout(), "(Hint: Press Ctrl-C to cancel and inspect keys with 'gpg --list-secret-keys')\n\n")

	idx, selectErr := HandleInteractiveSelection(options, "Select key to use for login:", c.output.Stderr())
	if selectErr != nil {
		return "", selectErr
	}

	return keys[idx].Fingerprint, nil
}

// Login initializes the user's identity with a signed login proof.
// If fingerprint is empty, it will interactively prompt the user to select from available secret keys.
func (c *CLI) Login(fingerprint string) *Error {
	// If no fingerprint provided, show interactive selection
	if fingerprint == "" {
		selectedFP, selectErr := c.selectSecretKey()
		if selectErr != nil {
			return selectErr
		}
		fingerprint = selectedFP
	}

	envFP := os.Getenv("DOTSECENV_FINGERPRINT")
	if envFP != "" && c.config.GetFingerprint() != "" && c.config.GetFingerprint() != fingerprint {
		c.Warnf("DOTSECENV_FINGERPRINT is set; new fingerprint will be cached but not used in this session")
	}

	publicKeyInfo, pubKeyErr := c.gpgClient.GetPublicKeyInfo(fingerprint)
	if pubKeyErr != nil {
		return NewError(fmt.Sprintf("failed to get public key for fingerprint '%s': %v\nMake sure your GPG key is available in gpg-agent", fingerprint, pubKeyErr), ExitGPGError)
	}

	// Display login info
	if publicKeyInfo.AlgorithmBits > 0 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Logging in with identity: %s (%s %d-bit)\n", publicKeyInfo.UID, publicKeyInfo.Algorithm, publicKeyInfo.AlgorithmBits)
		_, _ = fmt.Fprintf(c.output.Stdout(), "  Fingerprint: %s\n", fingerprint)
	} else {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Logging in with identity: %s (%s)\n", publicKeyInfo.UID, publicKeyInfo.Algorithm)
		_, _ = fmt.Fprintf(c.output.Stdout(), "  Fingerprint: %s\n", fingerprint)
	}

	// Create signed login proof
	_, _ = fmt.Fprintf(c.output.Stdout(), "Creating signed login proof...\n")
	login, err := createSignedLogin(c.gpgClient, fingerprint)
	if err != nil {
		return NewError(fmt.Sprintf("failed to create signed login: %v", err), ExitGPGError)
	}

	// Update config with new login (and clear deprecated fingerprint field)
	c.config.Login = login
	c.config.Fingerprint = "" // Clear deprecated field

	if err := config.Save(c.configPath, c.config); err != nil {
		return NewError(fmt.Sprintf("failed to save config: %v", err), ExitConfigError)
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Login successful! Signed proof stored in config.\n")

	return nil
}
