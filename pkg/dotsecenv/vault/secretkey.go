package vault

import (
	"fmt"
	"regexp"
	"strings"
)

// SecretKey represents a parsed and normalized secret key.
// Keys can be either namespaced (namespace::KEY_NAME) or non-namespaced (KEY_NAME).
type SecretKey struct {
	Namespace *string // nil for non-namespaced keys
	Name      string  // UPPERCASE
	Raw       string  // original input for error messages
}

// SecretKeySeparator is the delimiter between namespace and key name.
const SecretKeySeparator = "::"

// Compiled regex patterns for validation
var (
	// Pattern for namespace (after lowercasing): alphanumeric + underscores, must have at least one letter
	namespacePattern = regexp.MustCompile(`^[a-z0-9_]+$`)
	// Pattern for key name (after uppercasing): alphanumeric + underscores, must have at least one letter
	keyNamePattern = regexp.MustCompile(`^[A-Z0-9_]+$`)
	// Detect three or more consecutive underscores
	tripleUnderscorePattern = regexp.MustCompile(`_{3,}`)
	// Detect purely numeric string
	purelyNumericPattern = regexp.MustCompile(`^[0-9]+$`)
	// Detect only underscores
	onlyUnderscoresPattern = regexp.MustCompile(`^_+$`)
	// Detect if string has at least one letter
	hasLetterPattern = regexp.MustCompile(`[a-zA-Z]`)
)

// ParseSecretKey parses a raw key input and returns a normalized SecretKey.
// Accepts case-insensitive input and normalizes to canonical form.
//
// Valid formats:
//   - Namespaced: "namespace::KEY_NAME" -> "namespace::KEY_NAME"
//   - Non-namespaced: "KEY_NAME" -> "KEY_NAME"
func ParseSecretKey(raw string) (*SecretKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("secret key cannot be empty")
	}

	// Check for separator
	if strings.Contains(raw, SecretKeySeparator) {
		return parseNamespacedKey(raw)
	}

	return parseSimpleKey(raw)
}

// parseNamespacedKey parses a key with namespace::name format
func parseNamespacedKey(raw string) (*SecretKey, error) {
	parts := strings.Split(raw, SecretKeySeparator)

	// Must have exactly 2 parts
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid secret key format: multiple '::' separators found in %q", raw)
	}

	namespace := strings.ToLower(strings.TrimSpace(parts[0]))
	keyName := strings.ToUpper(strings.TrimSpace(parts[1]))

	if namespace == "" {
		return nil, fmt.Errorf("namespace cannot be empty in %q", raw)
	}
	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty in %q", raw)
	}

	if err := validateNamespace(namespace); err != nil {
		return nil, fmt.Errorf("invalid secret key %q: %w", raw, err)
	}

	if err := validateKeyName(keyName); err != nil {
		return nil, fmt.Errorf("invalid secret key %q: %w", raw, err)
	}

	return &SecretKey{
		Namespace: &namespace,
		Name:      keyName,
		Raw:       raw,
	}, nil
}

// parseSimpleKey parses a key without namespace
func parseSimpleKey(raw string) (*SecretKey, error) {
	keyName := strings.ToUpper(strings.TrimSpace(raw))

	if keyName == "" {
		return nil, fmt.Errorf("key name cannot be empty")
	}

	if err := validateKeyName(keyName); err != nil {
		return nil, fmt.Errorf("invalid secret key %q: %w", raw, err)
	}

	return &SecretKey{
		Namespace: nil,
		Name:      keyName,
		Raw:       raw,
	}, nil
}

// validateNamespace validates the namespace part (after lowercasing).
func validateNamespace(ns string) error {
	// Check for only underscores
	if onlyUnderscoresPattern.MatchString(ns) {
		return fmt.Errorf("namespace cannot consist only of underscores")
	}

	// Check for purely numeric
	if purelyNumericPattern.MatchString(ns) {
		return fmt.Errorf("namespace cannot be purely numeric")
	}

	// Cannot start with a number
	if len(ns) > 0 && ns[0] >= '0' && ns[0] <= '9' {
		return fmt.Errorf("namespace cannot start with a number")
	}

	// Cannot start with underscore
	if strings.HasPrefix(ns, "_") {
		return fmt.Errorf("namespace cannot start with underscore")
	}

	// Cannot end with underscore
	if strings.HasSuffix(ns, "_") {
		return fmt.Errorf("namespace cannot end with underscore")
	}

	// Check for triple underscores
	if tripleUnderscorePattern.MatchString(ns) {
		return fmt.Errorf("namespace cannot contain three or more consecutive underscores")
	}

	// Must have at least one letter
	if !hasLetterPattern.MatchString(ns) {
		return fmt.Errorf("namespace must contain at least one letter")
	}

	// Check overall pattern (alphanumeric + underscores)
	if !namespacePattern.MatchString(ns) {
		return fmt.Errorf("namespace must contain only lowercase letters, digits, and underscores")
	}

	return nil
}

// validateKeyName validates the key name part (after uppercasing).
func validateKeyName(name string) error {
	// Check for only underscores
	if onlyUnderscoresPattern.MatchString(name) {
		return fmt.Errorf("key name cannot consist only of underscores")
	}

	// Check for purely numeric
	if purelyNumericPattern.MatchString(name) {
		return fmt.Errorf("key name cannot be purely numeric")
	}

	// Cannot start with a number
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		return fmt.Errorf("key name cannot start with a number")
	}

	// Cannot end with underscore
	if strings.HasSuffix(name, "_") {
		return fmt.Errorf("key name cannot end with underscore")
	}

	// Check for triple underscores
	if tripleUnderscorePattern.MatchString(name) {
		return fmt.Errorf("key name cannot contain three or more consecutive underscores")
	}

	// Must have at least one letter
	if !hasLetterPattern.MatchString(name) {
		return fmt.Errorf("key name must contain at least one letter")
	}

	// Check overall pattern (alphanumeric + underscores)
	if !keyNamePattern.MatchString(name) {
		return fmt.Errorf("key name must contain only uppercase letters, digits, and underscores")
	}

	return nil
}

// String returns the canonical form of the secret key.
// For namespaced: "namespace::KEY_NAME"
// For non-namespaced: "KEY_NAME"
func (sk SecretKey) String() string {
	if sk.Namespace != nil {
		return *sk.Namespace + SecretKeySeparator + sk.Name
	}
	return sk.Name
}

// IsNamespaced returns true if this key has a namespace.
func (sk SecretKey) IsNamespaced() bool {
	return sk.Namespace != nil
}

// NormalizeSecretKey normalizes a secret key to canonical form.
// Returns the normalized key and any validation error.
func NormalizeSecretKey(key string) (string, error) {
	sk, err := ParseSecretKey(key)
	if err != nil {
		return "", err
	}
	return sk.String(), nil
}

// NormalizeKeyForLookup normalizes a secret key for lookup operations.
// If normalization fails (e.g., legacy key format), returns the original key unchanged.
// This provides backward compatibility for existing vaults with non-conforming keys.
func NormalizeKeyForLookup(key string) string {
	if normalized, err := NormalizeSecretKey(key); err == nil {
		return normalized
	}
	return key
}

// CompareSecretKeys compares two secret keys for equality, case-insensitively.
// Both keys are normalized before comparison.
func CompareSecretKeys(key1, key2 string) bool {
	norm1, err1 := NormalizeSecretKey(key1)
	norm2, err2 := NormalizeSecretKey(key2)

	// If either key fails to normalize, fall back to case-insensitive string compare
	if err1 != nil || err2 != nil {
		return strings.EqualFold(key1, key2)
	}

	return norm1 == norm2
}

// IsValidSecretKey returns true if the key is valid.
func IsValidSecretKey(key string) bool {
	_, err := ParseSecretKey(key)
	return err == nil
}

// FormatSecretKeyError formats a validation error with usage help.
func FormatSecretKeyError(err error) string {
	return fmt.Sprintf("%v\n\nExpected formats:\n"+
		"  Namespaced:     namespace::KEY_NAME  (e.g., myapp::DATABASE_URL)\n"+
		"  Non-namespaced: KEY_NAME             (e.g., DATABASE_URL)\n\n"+
		"Namespace rules:\n"+
		"  - Must start with a letter\n"+
		"  - Cannot start or end with underscore\n"+
		"  - No three consecutive underscores\n\n"+
		"Key name rules:\n"+
		"  - Must start with a letter\n"+
		"  - Cannot end with underscore\n"+
		"  - No three consecutive underscores", err)
}
