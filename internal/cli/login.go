package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// selectSecretKey lists encryption-capable secret keys and prompts the user
// to select one. Sign-only keys are filtered out: login eventually needs a
// key that can also encrypt secrets, so catching that mismatch here yields a
// clearer error than letting the first `secret put` fail later.
func (c *CLI) selectSecretKey() (string, *Error) {
	allKeys, err := c.gpgClient.ListSecretKeys()
	if err != nil {
		return "", NewError(fmt.Sprintf("failed to list secret keys: %v", err), ExitGPGError)
	}

	if len(allKeys) == 0 {
		return "", NewError("no secret keys found in GPG keyring.\nCreate a GPG key first with: dotsecenv identity create", ExitGPGError)
	}

	keys, skipped := filterEncryptionCapableKeys(c.gpgClient, allKeys)

	if len(keys) == 0 {
		return "", NewError(
			"no encryption-capable secret keys found in GPG keyring.\n"+
				"All available keys are signing-only or could not be loaded.\n"+
				"Create an encryption-capable GPG key with: dotsecenv identity create",
			ExitGPGError,
		)
	}

	if skipped > 0 {
		_, _ = fmt.Fprintf(c.output.Stderr(), "Skipped %d signing-only or unreadable key(s).\n", skipped)
	}

	// If only one capable key, auto-select it
	if len(keys) == 1 {
		_, _ = fmt.Fprintf(c.output.Stdout(), "Auto-selecting the only available key: %s (%s)\n", keys[0].UID, shortFingerprint(keys[0].Fingerprint))
		_, _ = fmt.Fprintln(c.output.Stdout())
		return keys[0].Fingerprint, nil
	}

	// Build display options for interactive selection
	var options []string
	for _, key := range keys {
		options = append(options, fmt.Sprintf("%s (%s)", key.UID, shortFingerprint(key.Fingerprint)))
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Available secret keys:\n")
	_, _ = fmt.Fprintf(c.output.Stdout(), "(Hint: Press Ctrl-C to cancel and inspect keys with 'gpg --list-secret-keys')\n\n")

	idx, selectErr := HandleInteractiveSelection(options, "Select key to use for login:", c.output.Stderr())
	if selectErr != nil {
		return "", selectErr
	}

	_, _ = fmt.Fprintln(c.output.Stdout())
	return keys[idx].Fingerprint, nil
}

// filterEncryptionCapableKeys returns the subset of `keys` whose public key
// loads successfully and is encryption-capable. Both load failures and
// sign-only keys are filtered out — neither is usable for storing secrets.
// `IsKeyEncryptionCapable` (used by GetPublicKeyInfo) inspects subkeys and
// algorithm flags directly, so a separate in-memory encrypt probe would be
// redundant.
func filterEncryptionCapableKeys(client gpg.Client, keys []gpg.SecretKeyInfo) (capable []gpg.SecretKeyInfo, skipped int) {
	for _, k := range keys {
		info, err := client.GetPublicKeyInfo(k.Fingerprint)
		if err != nil || info == nil || !info.CanEncrypt {
			skipped++
			continue
		}
		capable = append(capable, k)
	}
	return capable, skipped
}

// shortFingerprint returns the first 16 hex chars of a GPG fingerprint with
// a trailing ellipsis, suitable for terse list display.
func shortFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "..."
}

// requireEncryptionCapableKey returns an error if `info` represents a
// sign-only key. Login enforces this regardless of how the fingerprint
// reached it: interactive selection filters sign-only keys out, but
// `dotsecenv login FP` and `init config --login FP` bypass that filter
// and would otherwise produce a "successful" login that fails at the
// next `secret put`.
func requireEncryptionCapableKey(info *gpg.KeyInfo, fingerprint string) *Error {
	if info != nil && info.CanEncrypt {
		return nil
	}
	return NewError(fmt.Sprintf(
		"key %s is signing-only and cannot decrypt secrets.\n"+
			"Use a key with an encryption-capable subkey, or create one with: dotsecenv identity create",
		fingerprint,
	), ExitGPGError)
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

	publicKeyInfo, pubKeyErr := c.gpgClient.GetPublicKeyInfo(fingerprint)
	if pubKeyErr != nil {
		return NewError(fmt.Sprintf("failed to get public key for fingerprint '%s': %v\nMake sure your GPG key is available in gpg-agent", fingerprint, pubKeyErr), ExitGPGError)
	}

	if capErr := requireEncryptionCapableKey(publicKeyInfo, fingerprint); capErr != nil {
		return capErr
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

	// Update config with new login
	c.config.Login = login

	if err := config.Save(c.configPath, c.config); err != nil {
		return NewError(fmt.Sprintf("failed to save config: %v", err), ExitConfigError)
	}

	_, _ = fmt.Fprintf(c.output.Stdout(), "Login successful! Signed proof stored in config.\n")

	return nil
}
