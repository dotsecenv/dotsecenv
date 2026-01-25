package vault

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// WrapVaultError adds vault path context to an error for better debugging.
func WrapVaultError(path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("vault %q: %w", path, err)
}

// Format version constants
const (
	// LatestFormatVersion is the current vault format version used for new vaults
	LatestFormatVersion = 2
	// MinSupportedVersion is the minimum vault format version that can be read
	MinSupportedVersion = 1
	// FormatVersion is kept for backward compatibility, use LatestFormatVersion instead
	FormatVersion = LatestFormatVersion
)

// Entry types for JSONL records
const (
	EntryTypeIdentity = "identity"
	EntryTypeSecret   = "secret"
	EntryTypeValue    = "value"
)

// Header contains the vault index for efficient lookups.
// It maps fingerprints to line numbers for identities,
// and secret keys to their definition and value line numbers.
type Header struct {
	Version    int                    `json:"version"`
	Identities map[string]int         `json:"identities"` // fingerprint -> line number
	Secrets    map[string]SecretIndex `json:"secrets"`    // key -> secret index
}

// SecretIndex tracks line numbers for a secret and its values
type SecretIndex struct {
	Definition int   `json:"secret"` // line number of secret definition
	Values     []int `json:"values"` // line numbers of secret values
}

// NewHeader creates a new empty header
func NewHeader() *Header {
	return &Header{
		Version:    FormatVersion,
		Identities: make(map[string]int),
		Secrets:    make(map[string]SecretIndex),
	}
}

// Entry represents a single line entry in the vault file
type Entry struct {
	Type      string          `json:"type"`
	SecretKey string          `json:"secret,omitempty"` // only for value entries
	Data      json.RawMessage `json:"data"`
}

// IdentityData represents an identity entry's data
type IdentityData struct {
	AddedAt       time.Time  `json:"added_at"`
	Algorithm     string     `json:"algorithm"`
	AlgorithmBits int        `json:"algorithm_bits"`
	Curve         string     `json:"curve,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	Fingerprint   string     `json:"fingerprint"`
	Hash          string     `json:"hash"`
	PublicKey     string     `json:"public_key"`
	SignedBy      string     `json:"signed_by"`
	Signature     string     `json:"signature"`
	UID           string     `json:"uid"`
}

// SecretData represents a secret definition entry's data
type SecretData struct {
	AddedAt   time.Time `json:"added_at"`
	Hash      string    `json:"hash"`
	Key       string    `json:"key"`
	Signature string    `json:"signature"`
	SignedBy  string    `json:"signed_by"`
}

// ToIdentity converts IdentityData to the Identity type
func (d *IdentityData) ToIdentity() identity.Identity {
	return identity.Identity{
		AddedAt:       d.AddedAt,
		Algorithm:     d.Algorithm,
		AlgorithmBits: d.AlgorithmBits,
		Curve:         d.Curve,
		CreatedAt:     d.CreatedAt,
		ExpiresAt:     d.ExpiresAt,
		Fingerprint:   d.Fingerprint,
		Hash:          d.Hash,
		PublicKey:     d.PublicKey,
		SignedBy:      d.SignedBy,
		Signature:     d.Signature,
		UID:           d.UID,
	}
}

// IdentityDataFromIdentity converts Identity to IdentityData
func IdentityDataFromIdentity(id identity.Identity) IdentityData {
	return IdentityData{
		AddedAt:       id.AddedAt,
		Algorithm:     id.Algorithm,
		AlgorithmBits: id.AlgorithmBits,
		Curve:         id.Curve,
		CreatedAt:     id.CreatedAt,
		ExpiresAt:     id.ExpiresAt,
		Fingerprint:   id.Fingerprint,
		Hash:          id.Hash,
		PublicKey:     id.PublicKey,
		SignedBy:      id.SignedBy,
		Signature:     id.Signature,
		UID:           id.UID,
	}
}

// MarshalEntry creates a JSON line for an entry
func MarshalEntry(e Entry) ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalEntry parses a JSON line into an Entry
func UnmarshalEntry(data []byte) (*Entry, error) {
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entry: %w", err)
	}
	return &e, nil
}

// MarshalHeaderVersioned creates the JSON representation of the header in the specified version format.
func MarshalHeaderVersioned(h *Header, version int) ([]byte, error) {
	switch version {
	case 1:
		return MarshalHeaderV1(h)
	case 2:
		return MarshalHeaderV2(h)
	default:
		return nil, fmt.Errorf("unsupported vault format version: %d", version)
	}
}

// MarshalHeader creates the JSON representation of the header using the latest format.
// This is kept for backward compatibility with existing code.
func MarshalHeader(h *Header) ([]byte, error) {
	return MarshalHeaderVersioned(h, LatestFormatVersion)
}

// Vault section markers
const (
	// HeaderMarker is the constant marker line that precedes the vault header JSON.
	HeaderMarker = "# === VAULT HEADER ==="
	// DataMarker separates the header from data entries.
	DataMarker = "# === VAULT DATA ==="
)

// MarkerType identifies the type of vault marker line
type MarkerType int

const (
	// MarkerUnknown indicates the line is not a recognized marker
	MarkerUnknown MarkerType = iota
	// MarkerHeader indicates a current-format header marker
	MarkerHeader
	// MarkerHeaderLegacy indicates an old versioned header marker (e.g., "# === VAULT HEADER v1 ===")
	MarkerHeaderLegacy
	// MarkerData indicates a data section marker
	MarkerData
)

// DetectMarkerType identifies what type of marker a line is
func DetectMarkerType(line string) MarkerType {
	switch {
	case line == HeaderMarker:
		return MarkerHeader
	case line == DataMarker:
		return MarkerData
	case strings.HasPrefix(line, legacyMarkerPrefix) && strings.HasSuffix(line, legacyMarkerSuffix):
		middle := line[len(legacyMarkerPrefix) : len(line)-len(legacyMarkerSuffix)]
		if len(middle) > 0 && isNumeric(middle) {
			return MarkerHeaderLegacy
		}
	}
	return MarkerUnknown
}

// legacyMarkerPrefix is the prefix for old versioned header markers.
const legacyMarkerPrefix = "# === VAULT HEADER v"

// legacyMarkerSuffix is the suffix for old versioned header markers.
const legacyMarkerSuffix = " ==="

// ValidateHeaderMarker checks if a header marker line is valid.
// Accepts both the new versionless format and old versioned formats for backward compatibility.
// Returns nil if the marker is valid, or an error if invalid.
func ValidateHeaderMarker(markerLine string) error {
	markerType := DetectMarkerType(markerLine)
	if markerType == MarkerHeader || markerType == MarkerHeaderLegacy {
		return nil
	}
	return fmt.Errorf("invalid vault header marker: %q", markerLine)
}

// ValidateDataMarker checks if a data marker line is valid.
// Returns nil if the marker is valid, or an error if invalid.
func ValidateDataMarker(markerLine string) error {
	if DetectMarkerType(markerLine) == MarkerData {
		return nil
	}
	return fmt.Errorf("invalid vault data marker: %q", markerLine)
}

// isNumeric checks if a string contains only digits.
func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// HeaderMarkerForVersion returns the header marker (version-independent).
// Deprecated: The version parameter is ignored. Use HeaderMarker constant directly.
func HeaderMarkerForVersion(_ int) string {
	return HeaderMarker
}

// detectVersionFromJSON extracts the version from header JSON without full parsing.
// Uses a heuristic approach:
// 1. Fast path: assume version field is first ({"version":N,...)
// 2. Fallback: search for "version": anywhere in the JSON
// 3. Fails if version value is a string (no string-to-int conversion)
func detectVersionFromJSON(data []byte) (int, error) {
	str := string(data)
	if len(str) < 12 { // minimum: {"version":1}
		return 0, fmt.Errorf("header JSON too short")
	}

	// Fast path: version field is first
	const fastPrefix = `{"version":`
	var rest string
	if strings.HasPrefix(str, fastPrefix) {
		rest = str[len(fastPrefix):]
	} else {
		// Fallback: search for "version": anywhere in the JSON
		const versionKey = `"version":`
		idx := strings.Index(str, versionKey)
		if idx == -1 {
			return 0, fmt.Errorf("version field not found in header JSON")
		}
		rest = str[idx+len(versionKey):]
	}

	// Skip whitespace after colon
	rest = strings.TrimLeft(rest, " \t")

	if len(rest) == 0 {
		return 0, fmt.Errorf("version field has no value")
	}

	// Check if value is a string (starts with quote) - we don't parse string versions
	if rest[0] == '"' {
		return 0, fmt.Errorf("version must be an integer, not a string")
	}

	// Extract digits
	var versionStr string
	for _, c := range rest {
		if c >= '0' && c <= '9' {
			versionStr += string(c)
		} else {
			break
		}
	}

	if versionStr == "" {
		return 0, fmt.Errorf("no version number found in header JSON")
	}

	var version int
	if _, err := fmt.Sscanf(versionStr, "%d", &version); err != nil {
		return 0, fmt.Errorf("invalid version number: %s", versionStr)
	}

	return version, nil
}

// UnmarshalHeaderVersioned parses header JSON using the specified version's parser.
func UnmarshalHeaderVersioned(data []byte, version int) (*Header, error) {
	switch version {
	case 1:
		return UnmarshalHeaderV1(data)
	case 2:
		return UnmarshalHeaderV2(data)
	default:
		return nil, fmt.Errorf("unsupported vault format version: %d", version)
	}
}

// UnmarshalHeader parses JSON into a Header, auto-detecting the version.
func UnmarshalHeader(data []byte) (*Header, error) {
	version, err := detectVersionFromJSON(data)
	if err != nil {
		// Fallback: try v1 format (for backward compatibility)
		return UnmarshalHeaderV1(data)
	}

	if version < MinSupportedVersion {
		return nil, fmt.Errorf("vault format v%d is no longer supported (minimum: v%d)", version, MinSupportedVersion)
	}

	return UnmarshalHeaderVersioned(data, version)
}

// parseVaultHeader validates the marker line, detects version from the header JSON,
// and parses the header. Returns the parsed header and version number.
func parseVaultHeader(markerLine, headerLine string) (*Header, int, error) {
	if err := ValidateHeaderMarker(markerLine); err != nil {
		return nil, 0, fmt.Errorf("invalid vault file: %w", err)
	}

	version, err := detectVersionFromJSON([]byte(headerLine))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to detect vault version: %w", err)
	}

	if version < MinSupportedVersion {
		return nil, 0, fmt.Errorf("vault format v%d is no longer supported (minimum: v%d)",
			version, MinSupportedVersion)
	}

	header, err := UnmarshalHeaderVersioned([]byte(headerLine), version)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse vault header: %w", err)
	}

	return header, version, nil
}

// ParseIdentityData extracts IdentityData from an Entry
func ParseIdentityData(e *Entry) (*IdentityData, error) {
	if e.Type != EntryTypeIdentity {
		return nil, fmt.Errorf("entry is not an identity (type=%s)", e.Type)
	}
	var data IdentityData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse identity data: %w", err)
	}
	return &data, nil
}

// ParseSecretData extracts SecretData from an Entry
func ParseSecretData(e *Entry) (*SecretData, error) {
	if e.Type != EntryTypeSecret {
		return nil, fmt.Errorf("entry is not a secret (type=%s)", e.Type)
	}
	var data SecretData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse secret data: %w", err)
	}
	return &data, nil
}

// ParseSecretValue extracts SecretValue from an Entry
func ParseSecretValue(e *Entry) (*SecretValue, error) {
	if e.Type != EntryTypeValue {
		return nil, fmt.Errorf("entry is not a value (type=%s)", e.Type)
	}
	var data SecretValue
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse secret value: %w", err)
	}
	return &data, nil
}

// CreateIdentityEntry creates an Entry for an identity
func CreateIdentityEntry(id identity.Identity) (*Entry, error) {
	data := IdentityDataFromIdentity(id)
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal identity data: %w", err)
	}
	return &Entry{
		Type: EntryTypeIdentity,
		Data: jsonData,
	}, nil
}

// CreateSecretEntry creates an Entry for a secret definition
func CreateSecretEntry(s Secret) (*Entry, error) {
	data := SecretData{
		AddedAt:   s.AddedAt,
		Hash:      s.Hash,
		Key:       s.Key,
		Signature: s.Signature,
		SignedBy:  s.SignedBy,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret data: %w", err)
	}
	return &Entry{
		Type: EntryTypeSecret,
		Data: jsonData,
	}, nil
}

// CreateValueEntry creates an Entry for a secret value
func CreateValueEntry(secretKey string, sv SecretValue) (*Entry, error) {
	data := sv
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal value data: %w", err)
	}
	return &Entry{
		Type:      EntryTypeValue,
		SecretKey: secretKey,
		Data:      jsonData,
	}, nil
}

// VaultInfo contains lightweight metadata about a vault file.
// It can be obtained without fully parsing all vault entries.
type VaultInfo struct {
	Path          string     // Path to the vault file
	Version       int        // Vault format version
	MarkerFormat  MarkerType // Header marker format (current vs legacy)
	IdentityCount int        // Number of identities in the vault
	SecretCount   int        // Number of secrets in the vault
}

// InspectVault returns lightweight metadata about a vault without fully loading it.
// This is useful for quick vault inspection or validation.
func InspectVault(path string) (*VaultInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &VaultInfo{
				Path:          path,
				Version:       LatestFormatVersion,
				MarkerFormat:  MarkerUnknown,
				IdentityCount: 0,
				SecretCount:   0,
			}, nil
		}
		return nil, WrapVaultError(path, fmt.Errorf("failed to open: %w", err))
	}
	defer func() { _ = file.Close() }()

	// Check if file is empty
	info, err := file.Stat()
	if err != nil {
		return nil, WrapVaultError(path, fmt.Errorf("failed to stat: %w", err))
	}
	if info.Size() == 0 {
		return &VaultInfo{
			Path:          path,
			Version:       LatestFormatVersion,
			MarkerFormat:  MarkerUnknown,
			IdentityCount: 0,
			SecretCount:   0,
		}, nil
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	var markerLine, headerLine string

	for scanner.Scan() && lineNum < 2 {
		line := scanner.Text()
		switch lineNum {
		case 0:
			markerLine = line
		case 1:
			headerLine = line
		}
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return nil, WrapVaultError(path, fmt.Errorf("failed to scan: %w", err))
	}

	if markerLine == "" || headerLine == "" {
		return nil, WrapVaultError(path, fmt.Errorf("missing valid header"))
	}

	markerType := DetectMarkerType(markerLine)
	if markerType != MarkerHeader && markerType != MarkerHeaderLegacy {
		return nil, WrapVaultError(path, fmt.Errorf("invalid header marker: %q", markerLine))
	}

	version, err := detectVersionFromJSON([]byte(headerLine))
	if err != nil {
		return nil, WrapVaultError(path, fmt.Errorf("failed to detect version: %w", err))
	}

	header, err := UnmarshalHeaderVersioned([]byte(headerLine), version)
	if err != nil {
		return nil, WrapVaultError(path, fmt.Errorf("failed to parse header: %w", err))
	}

	return &VaultInfo{
		Path:          path,
		Version:       version,
		MarkerFormat:  markerType,
		IdentityCount: len(header.Identities),
		SecretCount:   len(header.Secrets),
	}, nil
}
