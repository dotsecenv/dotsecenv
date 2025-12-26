package gpg

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// ensureArmoredFormat checks if ciphertext is already in PGP armor format.
// If it's just a base64 payload (no armor headers), it wraps it with PGP MESSAGE armor.
func ensureArmoredFormat(ciphertext string) (string, error) {
	trimmed := strings.TrimSpace(ciphertext)
	if strings.HasPrefix(trimmed, "-----BEGIN") {
		// Already armored format - return as-is
		return ciphertext, nil
	}

	// If not armored, assume it's base64-encoded encrypted data
	// Need to add proper line breaks for armor format (76 chars per line)
	armorHeader := "-----BEGIN PGP MESSAGE-----\n\n"
	armorFooter := "\n-----END PGP MESSAGE-----"

	// Add line breaks every 76 characters as per RFC 4880
	var wrapped strings.Builder
	for i := 0; i < len(trimmed); i += 76 {
		end := i + 76
		if end > len(trimmed) {
			end = len(trimmed)
		}
		wrapped.WriteString(trimmed[i:end])
		wrapped.WriteString("\n")
	}

	return armorHeader + wrapped.String() + armorFooter, nil
}

// DecryptWithAgent decrypts data using gpg-agent (via GPG).
// fingerprint is optional - if provided, restricts which secret key is tried.
func (c *GPGClient) DecryptWithAgent(ciphertext []byte, fingerprint string) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	// Ciphertext is armored message (as bytes), use directly
	armoredCiphertext := string(ciphertext)

	// Build GPG command
	// If fingerprint is provided, use it to restrict which secret key is tried.
	var cmd *exec.Cmd
	if fingerprint != "" {
		cmd = exec.Command("gpg", "--decrypt", "--try-secret-key", fingerprint, "--quiet")
	} else {
		cmd = exec.Command("gpg", "--decrypt", "--quiet")
	}
	cmd.Stdin = strings.NewReader(armoredCiphertext)

	// Capture stderr to show actual GPG errors
	var stderr strings.Builder
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		stderrMsg := stderr.String()
		if stderrMsg != "" {
			return nil, fmt.Errorf("failed to decrypt with gpg-agent: %w\nGPG error: %s", err, stderrMsg)
		}
		return nil, fmt.Errorf("failed to decrypt with gpg-agent: %w\nMake sure gpg-agent is running and has access to the private key", err)
	}

	return output, nil
}

// DecryptWithKey decrypts data using a private key.
// Note: This function requires the key to have private parameters (for offline decryption).
// For gpg-agent based decryption, use DecryptWithAgent instead.
func DecryptWithKey(privateKey *crypto.Key, ciphertext []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Use RFC9580 profile for AEAD/AES-256-GCM support
	pgp := crypto.PGPWithProfile(profile.RFC9580())

	// Ciphertext is armored message (as bytes), use directly
	armoredCiphertext := string(ciphertext)

	// Create decryption handle
	decHandle, err := pgp.Decryption().DecryptionKey(privateKey).New()
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption handle: %w", err)
	}

	// Decrypt
	plaintext, err := decHandle.Decrypt([]byte(armoredCiphertext), crypto.Armor)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext.Bytes(), nil
}

// DecryptSecret decrypts a base64-encoded secret value.
// This is the inverse of EncryptSecret.
func (c *GPGClient) DecryptSecret(encryptedBase64 string, fingerprint string) ([]byte, error) {
	// Decode from base64
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret from base64: %w", err)
	}

	// Ensure the ciphertext is in armored format
	armored, err := ensureArmoredFormat(string(encrypted))
	if err != nil {
		return nil, fmt.Errorf("failed to format ciphertext: %w", err)
	}

	// Decrypt using gpg-agent
	return c.DecryptWithAgent([]byte(armored), fingerprint)
}

// DecryptSecretValue decrypts a SecretValue and returns the plaintext.
func (c *GPGClient) DecryptSecretValue(value *vault.SecretValue, fingerprint string) ([]byte, error) {
	return c.DecryptSecret(value.Value, fingerprint)
}
