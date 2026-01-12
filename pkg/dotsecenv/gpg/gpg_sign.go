package gpg

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// SignDataWithAgent signs data with gpg-agent and returns hex-encoded signature.
// fingerprint is the key fingerprint to use for signing.
func (c *GPGClient) SignDataWithAgent(fingerprint string, data []byte) (string, error) {
	if fingerprint == "" {
		return "", fmt.Errorf("fingerprint cannot be empty")
	}

	if len(data) == 0 {
		return "", fmt.Errorf("data cannot be empty")
	}

	// Check if we have a TTY available for pinentry
	hasTTY := false
	ttyPath := os.Getenv("GPG_TTY")
	if ttyPath == "" {
		ttyCmd := exec.Command("tty")
		if ttyOut, err := ttyCmd.Output(); err == nil {
			tty := strings.TrimSpace(string(ttyOut))
			if tty != "" && tty != "not a tty" {
				ttyPath = tty
				hasTTY = true
			}
		}
	} else {
		hasTTY = true
	}

	// Build GPG command
	// Use --pinentry-mode error when no TTY is available to fail fast instead of hanging
	var cmd *exec.Cmd
	if hasTTY {
		cmd = exec.Command(GetGPGProgram(), "--detach-sign", "-u", fingerprint)
		// Set GPG_TTY for pinentry
		cmd.Env = os.Environ()
		if os.Getenv("GPG_TTY") == "" {
			cmd.Env = append(cmd.Env, "GPG_TTY="+ttyPath)
		}
	} else {
		// No TTY: use --pinentry-mode error to fail fast if passphrase needed
		cmd = exec.Command(GetGPGProgram(), "--detach-sign", "-u", fingerprint, "--pinentry-mode", "error")
		cmd.Env = os.Environ()
	}
	cmd.Stdin = strings.NewReader(string(data))

	// Capture stderr to include in error messages for better debugging
	var stderr strings.Builder
	cmd.Stderr = &stderr

	output, err := cmd.Output()
	if err != nil {
		stderrMsg := stderr.String()
		// Check for pinentry-related errors and provide helpful message
		if strings.Contains(stderrMsg, "No pinentry") || strings.Contains(stderrMsg, "pinentry") {
			return "", fmt.Errorf("GPG passphrase required but no TTY available for pinentry.\n"+
				"Options:\n"+
				"  1. Run in a terminal with GPG_TTY set: export GPG_TTY=$(tty)\n"+
				"  2. Pre-cache passphrase: gpg --sign --local-user %s </dev/null\n"+
				"  3. Use a key without passphrase for automation", fingerprint)
		}
		if stderrMsg != "" {
			return "", fmt.Errorf("failed to sign data with gpg-agent: %w\nGPG error: %s", err, stderrMsg)
		}
		return "", fmt.Errorf("failed to sign data with gpg-agent: %w\nMake sure your GPG key is available in gpg-agent", err)
	}

	if len(output) == 0 {
		return "", fmt.Errorf("no signature generated")
	}

	// Convert binary signature to hex
	return hex.EncodeToString(output), nil
}

// SignData signs data with a private key and returns hex-encoded signature.
// Note: This function requires the key to have private parameters (for offline signing).
// For gpg-agent based signing, use SignDataWithAgent instead.
func SignData(privateKey *crypto.Key, data []byte) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("key is nil")
	}

	// Use RFC9580 profile for consistency across all cryptographic operations
	pgp := crypto.PGPWithProfile(profile.RFC9580())

	// Create signer with detached signature
	signer, err := pgp.Sign().SigningKey(privateKey).Detached().New()
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	// Sign the data (with encoding 0 for raw binary)
	signature, err := signer.Sign(data, 0)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	signer.ClearPrivateParams()
	// Convert binary signature to hex
	return hex.EncodeToString(signature), nil
}

// SignIdentity signs an identity's canonical data and returns the hash and signature.
// It computes the hash from the canonical data and signs that hash.
func (c *GPGClient) SignIdentity(id *identity.Identity, signerFingerprint string) (hash string, signature string, err error) {
	// Compute the canonical hash
	hash = identity.ComputeIdentityHash(id)

	// Sign the hash
	signature, err = c.SignDataWithAgent(signerFingerprint, []byte(hash))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign identity: %w", err)
	}

	return hash, signature, nil
}

// SignSecret signs a secret's canonical data and returns the hash and signature.
func (c *GPGClient) SignSecret(secret *vault.Secret, signerFingerprint string, algorithmBits int) (hash string, signature string, err error) {
	// Compute the canonical hash
	hash = vault.ComputeSecretHash(secret, algorithmBits)

	// Sign the hash
	signature, err = c.SignDataWithAgent(signerFingerprint, []byte(hash))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign secret: %w", err)
	}

	return hash, signature, nil
}

// SignSecretValue signs a secret value's canonical data and returns the hash and signature.
func (c *GPGClient) SignSecretValue(value *vault.SecretValue, signerFingerprint string, algorithmBits int) (hash string, signature string, err error) {
	// Compute the canonical hash
	hash = vault.ComputeSecretValueHash(value, algorithmBits)

	// Sign the hash
	signature, err = c.SignDataWithAgent(signerFingerprint, []byte(hash))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign secret value: %w", err)
	}

	return hash, signature, nil
}
