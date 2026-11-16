package cli

import (
	"fmt"
	"strings"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/crypto"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// rsaLegacyDocsURL points at the compliance page section that explains why
// RSA keys are legacy.
const rsaLegacyDocsURL = "https://dotsecenv.com/concepts/compliance/#rsa-keys-are-legacy"

// rsaLegacyReason is the shared explanation printed wherever dotsecenv
// rejects or warns about an RSA key.
const rsaLegacyReason = `RSA keys are legacy. OpenPGP encrypts to RSA keys with PKCS #1 v1.5
padding, which Go deprecated in 1.26 as unsafe, and OpenPGP offers no
OAEP alternative. RSA keys are also larger and slower than elliptic-curve
keys. Use ED25519, or P384/P521 where you need a NIST curve.`

// rsaOptInHint tells the user how to keep accepting RSA keys.
const rsaOptInHint = `To accept RSA keys anyway, add this to approved_algorithms in your config:
  - algo: RSA
    min_bits: 3072`

// isRSAAlgorithm reports whether an algorithm string (as stored on an
// identity or returned by the GPG client) names an RSA key.
func isRSAAlgorithm(algo string) bool {
	return strings.EqualFold(crypto.ExtractAlgorithmName(algo), "RSA")
}

// legacyIdentityCheck builds the doctor warning for a vault that holds RSA
// identities. ok is false when the vault has none.
func legacyIdentityCheck(index int, path string, identities []vault.Identity) (check DoctorCheckJSON, ok bool) {
	var legacy []string
	for _, id := range identities {
		if isRSAAlgorithm(id.Algorithm) {
			legacy = append(legacy, fmt.Sprintf("%s (%s)", id.UID, id.Fingerprint))
		}
	}
	if len(legacy) == 0 {
		return DoctorCheckJSON{}, false
	}

	noun := "identities"
	if len(legacy) == 1 {
		noun = "identity"
	}
	return DoctorCheckJSON{
		Name:    fmt.Sprintf("vault_%d_legacy_keys", index+1),
		Status:  "warning",
		Message: fmt.Sprintf("%s: %d RSA %s (legacy)", path, len(legacy), noun),
		Details: fmt.Sprintf("%s. Have each owner create an ED25519 or P384 identity and share secrets with it. See %s",
			strings.Join(legacy, ", "), rsaLegacyDocsURL),
	}, true
}

// rsaNotAllowedSuffix returns the explanation appended to an
// "algorithm not allowed" error for RSA keys, or "" for other algorithms.
func rsaNotAllowedSuffix(algo string) string {
	if !isRSAAlgorithm(algo) {
		return ""
	}
	return "\n\n" + rsaLegacyReason + "\n\n" + rsaOptInHint + "\nSee " + rsaLegacyDocsURL
}
