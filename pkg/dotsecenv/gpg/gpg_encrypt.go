package gpg

import (
	"encoding/base64"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

// EncryptToRecipients encrypts data to multiple recipients and returns armored ciphertext.
// publicKeyBase64List contains base64-encoded public keys.
// signingKey is optional - if provided, the message will be signed.
func (c *GPGClient) EncryptToRecipients(plaintext []byte, publicKeyBase64List []string, signingKey *crypto.Key) (string, error) {
	if len(publicKeyBase64List) == 0 {
		return "", fmt.Errorf("no recipients specified")
	}

	// Use RFC9580 profile which enforces AEAD with AES-256-GCM
	// RFC 9580 is the updated OpenPGP standard with mandatory AEAD support
	pgp := crypto.PGPWithProfile(profile.RFC9580())

	// Build keyring for multiple recipients
	recipients, err := crypto.NewKeyRing(nil)
	if err != nil {
		return "", fmt.Errorf("failed to create key ring: %w", err)
	}

	for i, keyBase64 := range publicKeyBase64List {
		// Decode base64 to binary
		keyBinary, err := base64.StdEncoding.DecodeString(keyBase64)
		if err != nil {
			return "", fmt.Errorf("failed to decode recipient key %d from base64: %w", i, err)
		}

		key, err := crypto.NewKey(keyBinary)
		if err != nil {
			return "", fmt.Errorf("failed to parse recipient key %d: %w", i, err)
		}

		// Check if key can encrypt (has encryption-capable subkeys)
		if !IsKeyEncryptionCapable(key) {
			uid := "unknown"
			if keyEntity := key.GetEntity(); keyEntity != nil {
				uid, _ = GetKeyUID(key)
			}
			return "", fmt.Errorf("recipient %s has a signing-only key and cannot decrypt messages (requires an encryption-capable subkey)", uid)
		}

		if err := recipients.AddKey(key); err != nil {
			return "", fmt.Errorf("failed to add recipient key %d to keyring: %w", i, err)
		}
	}

	// Explicitly disable compression per RFC 9580 (avoids CRIME-style side-channel attacks)
	encHandle, err := pgp.Encryption().Recipients(recipients).SigningKey(signingKey).CompressWith(constants.NoCompression).New()
	if err != nil {
		return "", fmt.Errorf("failed to create encryption handle: %w", err)
	}

	// Encrypt
	pgpMessage, err := encHandle.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	// Return armored encrypted data as string
	armoredBytes, err := pgpMessage.ArmorBytes()
	if err != nil {
		return "", fmt.Errorf("failed to armor message: %w", err)
	}

	return string(armoredBytes), nil
}

// EncryptToRecipientsWithFingerprints encrypts data to multiple recipients using their fingerprints.
// This is a convenience function that looks up public keys from GPG.
func (c *GPGClient) EncryptToRecipientsWithFingerprints(plaintext []byte, fingerprints []string, signingFingerprint string) (string, error) {
	if len(fingerprints) == 0 {
		return "", fmt.Errorf("no recipients specified")
	}

	// Collect public keys for all recipients
	publicKeys := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		keyInfo, err := c.GetPublicKeyInfo(fp)
		if err != nil {
			return "", fmt.Errorf("failed to get public key for %s: %w", fp, err)
		}
		publicKeys = append(publicKeys, keyInfo.PublicKeyBase64)
	}

	// Get signing key if fingerprint provided
	var signingKey *crypto.Key
	if signingFingerprint != "" {
		var err error
		signingKey, err = c.GetSecretKeyFromAgent(signingFingerprint)
		if err != nil {
			return "", fmt.Errorf("failed to get signing key: %w", err)
		}
	}

	return c.EncryptToRecipients(plaintext, publicKeys, signingKey)
}

// EncryptSecret encrypts a secret value for multiple recipients.
// Returns the base64-encoded encrypted ciphertext.
func (c *GPGClient) EncryptSecret(plaintext []byte, recipientPublicKeys []string, signingKey *crypto.Key) (string, error) {
	encrypted, err := c.EncryptToRecipients(plaintext, recipientPublicKeys, signingKey)
	if err != nil {
		return "", err
	}

	// Return as base64 for storage in vault
	return base64.StdEncoding.EncodeToString([]byte(encrypted)), nil
}
