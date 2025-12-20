package gpg

import (
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	// "github.com/dotsecenv/dotsecenv/pkg/dotsecenv/crypto" removed to avoid conflict

	// But import path "gopenpgp/v3/crypto" also has package "crypto".
	// Conflict!
	// Solution: alias one of them.
	// gopenpgp crypto is imported as "crypto".
	// dotsecenv crypto should be aliased as "dscrypto" or similar.
	// Or rename dotsecenv crypto package to "common"? user asked for "crypto" namespace? No, user asked for "config, gpg, identity".
	// I chose "crypto" for shared logic.
	// I will alias dotsecenv/crypto as "dscrypto".
	dscrypto "github.com/dotsecenv/dotsecenv/pkg/dotsecenv/crypto"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// KeyInfo holds information about a GPG key.
type KeyInfo struct {
	Fingerprint     string
	UID             string
	Algorithm       string
	AlgorithmBits   int
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	CanEncrypt      bool
	PublicKeyBase64 string
}

// Client defines the interface for GPG operations.
// Client defines the interface for GPG operations.
type Client interface {
	GetPublicKeyInfo(fingerprint string) (*KeyInfo, error)
	EncryptToRecipients(plaintext []byte, recipients []string, signingKey *crypto.Key) (string, error)
	SignDataWithAgent(fingerprint string, data []byte) (string, error)
	DecryptWithAgent(ciphertext []byte, fingerprint string) ([]byte, error)
	ExtractAlgorithmAndCurve(fullAlgorithm string) (algorithm string, curve string)
	GetKeyCreationTime(fingerprint string) time.Time
	SignIdentity(identity *identity.Identity, signerFingerprint string) (hash string, signature string, err error)
	SignSecret(secret *vault.Secret, signerFingerprint string, algorithmBits int) (hash string, signature string, err error)
	SignSecretValue(value *vault.SecretValue, signerFingerprint string, algorithmBits int) (hash string, signature string, err error)
	DecryptSecret(encryptedBase64 string, fingerprint string) ([]byte, error)
	DecryptSecretValue(value *vault.SecretValue, fingerprint string) ([]byte, error)
}

// GPGClient provides GPG operations.
type GPGClient struct {
	Validator *dscrypto.AlgorithmValidator
}

// DefaultGPGClient is the default client instance.
var DefaultGPGClient = &GPGClient{}

// GPG Algorithm IDs (RFC 4880/9580)
const (
	GPGAlgoRSA            = 1
	GPGAlgoRSAEncryptOnly = 2 // Deprecated
	GPGAlgoRSASignOnly    = 3 // Deprecated
	GPGAlgoElgamal        = 16
	GPGAlgoDSA            = 17
	GPGAlgoECDH           = 18
	GPGAlgoECDSA          = 19
	GPGAlgoEdDSA          = 22
	GPGAlgoX25519         = 24 // Non-standard GPG extension
	GPGAlgoX448           = 25 // Non-standard GPG extension
)

// curveMappings maps GPG/Standard curve names to DotSecEnv display names
var curveMappings = map[string]string{
	"P-256":      "ECC P-256",
	"nistp256":   "ECC P-256",
	"P-384":      "ECC P-384",
	"nistp384":   "ECC P-384",
	"P-521":      "ECC P-521",
	"nistp521":   "ECC P-521",
	"secp256k1":  "ECC secp256k1",
	"ed25519":    "EdDSA Ed25519",
	"Ed25519":    "EdDSA Ed25519",
	"cv25519":    "X25519",
	"x25519":     "X25519",
	"curve25519": "X25519",
	"x448":       "X448",
	"curve448":   "X448",
}

// getGPGAlgoName returns the base algorithm name for a given GPG ID
func getGPGAlgoName(id int) string {
	switch id {
	case GPGAlgoRSA:
		return "RSA"
	case GPGAlgoRSASignOnly:
		return "RSA-S"
	case GPGAlgoElgamal:
		return "Elgamal"
	case GPGAlgoDSA:
		return "DSA"
	case GPGAlgoECDH:
		return "ECDH"
	case GPGAlgoECDSA:
		return "ECDSA"
	case GPGAlgoEdDSA:
		return "EdDSA"
	case GPGAlgoX25519:
		return "X25519"
	case GPGAlgoX448:
		return "X448"
	default:
		return "Unknown"
	}
}

// parseGPGAlgorithm parses algorithm from GPG's algorithm ID, optional curve, and optional bit length.
// When curve is empty and bits are provided, it infers the curve from the bit length for ECDSA/ECDH.
func parseGPGAlgorithm(algo int, curve string, bits ...int) string {
	// Get base algorithm name
	baseAlgo := getGPGAlgoName(algo)

	// If we have curve information, use it to provide more specific name
	if curve != "" {
		cleanCurve := strings.TrimSpace(curve)

		if !isValidCurveName(cleanCurve) {
			if baseAlgo != "Unknown" {
				return baseAlgo
			}
			return fmt.Sprintf("Unknown(%d)", algo)
		}

		if mapped, ok := curveMappings[cleanCurve]; ok {
			return mapped
		}

		if (algo == GPGAlgoECDH || algo == GPGAlgoECDSA) && cleanCurve != "" {
			if strings.HasPrefix(cleanCurve, "P-") || strings.HasPrefix(cleanCurve, "secp") {
				return fmt.Sprintf("ECC %s", cleanCurve)
			}
			return baseAlgo
		}

		if algo == GPGAlgoEdDSA && cleanCurve != "" {
			return fmt.Sprintf("EdDSA %s", cleanCurve)
		}
	}

	// Fallback: for ECDSA/ECDH/EdDSA without curve info, try to infer from bit length
	if curve == "" && len(bits) > 0 && (algo == GPGAlgoECDH || algo == GPGAlgoECDSA || algo == GPGAlgoEdDSA) {
		inferredCurve := inferCurveFromBitLength(bits[0], algo)
		if inferredCurve != "" {
			if algo == GPGAlgoEdDSA {
				return fmt.Sprintf("EdDSA %s", inferredCurve)
			}
			return fmt.Sprintf("ECC %s", inferredCurve)
		}
	}

	if baseAlgo != "Unknown" {
		return baseAlgo
	}

	return fmt.Sprintf("Unknown(%d)", algo)
}

// inferCurveFromBitLength infers the elliptic curve name from bit length.
func inferCurveFromBitLength(bits int, algoID int) string {
	switch bits {
	case 255, 256:
		// 255/256 bits can be generic ECC (P-256 is common default) or EdDSA (Ed25519)
		if algoID == GPGAlgoEdDSA {
			return "Ed25519"
		}
		// For standard ECC (18/19), default to P-256 as it's the most common mapping for 256 bits
		// This restores previous behavior for Brainpool/other 256-bit curves where we just guessed P-256
		return "P-256"
	case 384:
		return "P-384"
	case 448, 456:
		// Ed448/X448
		if algoID == GPGAlgoEdDSA {
			return "Ed448"
		}
		return "Ed448"
	case 521:
		return "P-521"
	default:
		return ""
	}
}

// isValidCurveName validates that a curve name contains only expected characters.
func isValidCurveName(curve string) bool {
	if curve == "" {
		return false
	}
	for _, r := range curve {
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		if !isLower && !isUpper && !isDigit && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// ExtractAlgorithmAndCurve splits a full algorithm string into base algorithm and curve components.
// Examples:
//
//	"ECC P-384" → ("ECC", "P-384")
//	"EdDSA Ed25519" → ("EdDSA", "Ed25519")
//	"RSA" → ("RSA", "")
//	"X25519" → ("X25519", "")
func (c *GPGClient) ExtractAlgorithmAndCurve(fullAlgorithm string) (algorithm string, curve string) {
	parts := strings.Fields(fullAlgorithm)

	if len(parts) == 0 {
		return "", ""
	}

	if len(parts) == 1 {
		return parts[0], ""
	}

	if len(parts) >= 2 {
		return parts[0], strings.Join(parts[1:], " ")
	}

	return "", ""
}

// getPublicKeyBinary retrieves the public key from GPG and returns it as binary.
func getPublicKeyBinary(fingerprint string) ([]byte, error) {
	cmd := exec.Command("gpg", "--export", fingerprint)
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %w", err)
	}

	if len(output) == 0 {
		return nil, fmt.Errorf("public key not found for fingerprint: %s", fingerprint)
	}

	return output, nil
}

// extractCurveFromKey extracts the elliptic curve name from a key in pure Go.
func extractCurveFromKey(pubKey interface{}) string {
	if pubKey == nil {
		return ""
	}

	keyValue := reflect.ValueOf(pubKey)
	if keyValue.Kind() == reflect.Ptr {
		keyValue = keyValue.Elem()
	}

	// Check if this is a wrapper struct that contains the actual key
	if keyValue.Kind() == reflect.Struct {
		if pkField := keyValue.FieldByName("PublicKey"); pkField.IsValid() && !pkField.IsZero() {
			if pkField.Kind() == reflect.Interface || pkField.Kind() == reflect.Ptr {
				if innerCurve := extractCurveFromKey(pkField.Interface()); innerCurve != "" {
					return innerCurve
				}
			}
		}
	}

	// Look for Curve field
	if keyValue.Kind() == reflect.Struct {
		if curveField := keyValue.FieldByName("Curve"); curveField.IsValid() && !curveField.IsZero() {
			if curve, ok := curveField.Interface().(elliptic.Curve); ok && curve != nil {
				return getCurveName(curve)
			}
			if curveStr, ok := curveField.Interface().(string); ok && curveStr != "" {
				return curveStr
			}
		}

		if curveInfo := keyValue.FieldByName("CurveInfo"); curveInfo.IsValid() && !curveInfo.IsZero() {
			if info, ok := curveInfo.Interface().(string); ok && info != "" {
				return info
			}
		}
	}

	// Fallback: try to determine curve from key type name
	keyType := keyValue.Type().String()

	switch {
	case strings.Contains(keyType, "P256") || strings.Contains(keyType, "P-256"):
		return "P-256"
	case strings.Contains(keyType, "P384") || strings.Contains(keyType, "P-384"):
		return "P-384"
	case strings.Contains(keyType, "P521") || strings.Contains(keyType, "P-521"):
		return "P-521"
	case strings.Contains(keyType, "secp256k1"):
		return "secp256k1"
	case strings.Contains(keyType, "25519") || strings.Contains(keyType, "Ed25519"):
		if strings.Contains(keyType, "X25519") || strings.Contains(keyType, "Curve25519") {
			return "X25519"
		}
		return "Ed25519"
	case strings.Contains(keyType, "448") || strings.Contains(keyType, "Ed448"):
		if strings.Contains(keyType, "X448") {
			return "X448"
		}
		return "Ed448"
	}

	return ""
}

// getCurveName converts an elliptic.Curve to its string name.
func getCurveName(curve elliptic.Curve) string {
	if curve == nil {
		return ""
	}

	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		methodValue := reflect.ValueOf(curve).MethodByName("Name")
		if methodValue.IsValid() {
			results := methodValue.Call([]reflect.Value{})
			if len(results) > 0 && results[0].Kind() == reflect.String {
				name := results[0].String()
				switch name {
				case "P-256", "secp256r1", "prime256v1":
					return "P-256"
				case "P-384", "secp384r1":
					return "P-384"
				case "P-521", "secp521r1":
					return "P-521"
				case "secp256k1":
					return "secp256k1"
				}
				return name
			}
		}
	}

	return ""
}

// getAlgorithmBitsFromKey retrieves the algorithm bit length from a key object.
func getAlgorithmBitsFromKey(entity interface{}) int {
	if entity == nil {
		return 0
	}

	parentValue := reflect.ValueOf(entity)
	if parentValue.Kind() == reflect.Ptr {
		bitLengthMethod := parentValue.MethodByName("BitLength")
		if bitLengthMethod.IsValid() {
			results := bitLengthMethod.Call([]reflect.Value{})
			if len(results) >= 1 && results[0].Kind() == reflect.Int {
				return int(results[0].Int())
			}
			if len(results) >= 1 {
				val := results[0]
				if val.Kind() == reflect.Int || val.Kind() == reflect.Int64 {
					bits := val.Int()
					if bits > 0 {
						return int(bits)
					}
				}
			}
		}
	}

	// For ECC keys, try to extract curve and map to bit length
	curve := extractCurveFromKey(entity)
	if curve != "" {
		curveBitMap := map[string]int{
			"P-256":     256,
			"nistp256":  256,
			"P-384":     384,
			"nistp384":  384,
			"P-521":     521,
			"nistp521":  521,
			"secp256k1": 256,
			"ed25519":   256,
			"Ed25519":   256,
			"ed448":     456,
			"Ed448":     456,
			"x25519":    256,
			"X25519":    256,
			"x448":      448,
			"X448":      448,
		}

		if bits, ok := curveBitMap[curve]; ok {
			return bits
		}
	}

	return 0
}

// getAlgorithmBitsFromFingerprint retrieves the algorithm bit length from GPG.
func getAlgorithmBitsFromFingerprint(fingerprint string) int {
	cmd := exec.Command("gpg", "--with-colons", "--list-public-keys", fingerprint)
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "pub:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 && parts[2] != "" {
				var bits int
				if _, err := fmt.Sscanf(parts[2], "%d", &bits); err == nil && bits > 0 {
					return bits
				}
			}
		}
	}

	return 0
}

// GetKeyCreationTime retrieves the key creation time from GPG.
func (c *GPGClient) GetKeyCreationTime(fingerprint string) time.Time {
	cmd := exec.Command("gpg", "--with-colons", "--list-public-keys", fingerprint)
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		return time.Now().UTC()
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "pub:") {
			parts := strings.Split(line, ":")
			if len(parts) > 5 && parts[5] != "" {
				var timestamp int64
				if _, err := fmt.Sscanf(parts[5], "%d", &timestamp); err == nil && timestamp > 0 {
					return time.Unix(timestamp, 0).UTC()
				}
			}
		}
	}

	return time.Now().UTC()
}

// GetKeyExpiration retrieves the key expiration time from GPG.
func (c *GPGClient) GetKeyExpiration(fingerprint string) *time.Time {
	cmd := exec.Command("gpg", "--with-colons", "--list-public-keys", fingerprint)
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "pub:") {
			parts := strings.Split(line, ":")
			if len(parts) > 6 && parts[6] != "" {
				var timestamp int64
				if _, err := fmt.Sscanf(parts[6], "%d", &timestamp); err == nil && timestamp > 0 {
					t := time.Unix(timestamp, 0).UTC()
					return &t
				}
			}
		}
	}

	return nil
}

// isKeyExpired checks if a key is expired using gpg --list-keys.
func (c *GPGClient) isKeyExpired(fingerprint string) bool {
	cmd := exec.Command("gpg", "--list-keys", "--with-colons", fingerprint)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) >= 7 && parts[0] == "pub" {
			expirationStr := parts[6]
			if expirationStr == "" {
				return false
			}
			expirationTimestamp, err := strconv.ParseInt(expirationStr, 10, 64)
			if err != nil {
				return false
			}
			expirationTime := time.Unix(expirationTimestamp, 0)
			return time.Now().After(expirationTime)
		}
	}

	return false
}

// GetPublicKeyInfo retrieves information about a public key from gpg-agent.
func (c *GPGClient) GetPublicKeyInfo(fingerprint string) (*KeyInfo, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("fingerprint cannot be empty")
	}

	if c.isKeyExpired(fingerprint) {
		return nil, fmt.Errorf("key is expired\nTo use this key for signing, you must extend its expiration date in GPG:\n  gpg --edit-key %s\n  gpg> expire\n  (follow the prompts to set a new expiration date)\n  gpg> save", fingerprint)
	}

	keyBinary, err := getPublicKeyBinary(fingerprint)
	if err != nil {
		return nil, err
	}

	key, err := crypto.NewKey(keyBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	uid, err := GetKeyUID(key)
	if err != nil {
		return nil, fmt.Errorf("failed to extract UID: %w", err)
	}

	var algo string
	var bits int

	entity := key.GetEntity()
	if entity != nil && entity.PrimaryKey != nil {
		algoID := int(entity.PrimaryKey.PubKeyAlgo)
		curve := extractCurveFromKey(entity.PrimaryKey)

		bits = getAlgorithmBitsFromKey(entity.PrimaryKey)
		if bits == 0 {
			bits = getAlgorithmBitsFromFingerprint(fingerprint)
		}

		algo = parseGPGAlgorithm(algoID, curve, bits)
	} else {
		algo = "RSA-4096"
		bits = 4096
	}

	// Validate algorithm using the configured validator if present
	if c.Validator != nil {
		if err := c.Validator.ValidateAsymmetric(algo); err != nil {
			return nil, fmt.Errorf("algorithm validation failed: %w", err)
		}
	}

	canEncrypt := IsKeyEncryptionCapable(key)
	createdAt := c.GetKeyCreationTime(fingerprint)
	expiresAt := c.GetKeyExpiration(fingerprint)

	return &KeyInfo{
		Fingerprint:     fingerprint,
		UID:             uid,
		Algorithm:       algo,
		AlgorithmBits:   bits,
		CreatedAt:       createdAt,
		ExpiresAt:       expiresAt,
		CanEncrypt:      canEncrypt,
		PublicKeyBase64: base64.StdEncoding.EncodeToString(keyBinary),
	}, nil
}

// IsKeyEncryptionCapable checks if a key is capable of encryption.
func IsKeyEncryptionCapable(key *crypto.Key) bool {
	if key == nil {
		return false
	}

	if key.CanEncrypt(time.Now().Unix()) {
		return true
	}

	// Fallback: Manual inspection of subkeys
	entity := key.GetEntity()
	if entity != nil {
		for _, subkey := range entity.Subkeys {
			if subkey.PublicKey != nil {
				algo := int(subkey.PublicKey.PubKeyAlgo)
				if algo == 18 { // ECDH
					return true
				}
			}
		}
	}

	return false
}

// GetSecretKeyFromAgent retrieves a secret key from gpg-agent for a given fingerprint.
func (c *GPGClient) GetSecretKeyFromAgent(fingerprint string) (*crypto.Key, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("fingerprint cannot be empty")
	}

	cmd := exec.Command("gpg", "--with-colons", "--list-secret-keys", fingerprint)
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list secret keys: %w", err)
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return nil, fmt.Errorf("secret key not found for fingerprint: %s\nMake sure the key is available in gpg-agent", fingerprint)
	}

	if !strings.Contains(outputStr, fingerprint) {
		return nil, fmt.Errorf("secret key not available for fingerprint: %s", fingerprint)
	}

	keyBinary, err := getPublicKeyBinary(fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for secret key operations: %w", err)
	}

	key, err := crypto.NewKey(keyBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	return key, nil
}

// GetKeyFingerprint gets the fingerprint from a base64-encoded public key.
func GetKeyFingerprint(publicKeyBase64 string) (string, error) {
	keyBinary, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode key from base64: %w", err)
	}

	key, err := crypto.NewKey(keyBinary)
	if err != nil {
		return "", fmt.Errorf("failed to parse key: %w", err)
	}

	return key.GetFingerprint(), nil
}

// ExportPublicKeyBase64 exports a key as base64-encoded binary.
func ExportPublicKeyBase64(key *crypto.Key) (string, error) {
	if key == nil {
		return "", fmt.Errorf("key is nil")
	}

	binary, err := key.Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(binary), nil
}

// GetKeyUID extracts the UID (user ID/email) from a key.
func GetKeyUID(key *crypto.Key) (string, error) {
	if key == nil {
		return "", fmt.Errorf("key is nil")
	}

	entity := key.GetEntity()
	if entity == nil {
		return "", fmt.Errorf("key has no entity information")
	}

	for _, identity := range entity.Identities {
		if identity != nil {
			return identity.Name, nil
		}
	}

	return "", fmt.Errorf("key has no user IDs")
}
