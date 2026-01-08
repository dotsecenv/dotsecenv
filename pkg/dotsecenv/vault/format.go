package vault

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

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

// ValueData represents a secret value entry's data
type ValueData struct {
	AddedAt     time.Time `json:"added_at"`
	AvailableTo []string  `json:"available_to"`
	Deleted     bool      `json:"deleted,omitempty"`
	Hash        string    `json:"hash"`
	Signature   string    `json:"signature"`
	SignedBy    string    `json:"signed_by"`
	Value       string    `json:"value"`
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

// ToSecretValue converts ValueData to SecretValue
func (d *ValueData) ToSecretValue() SecretValue {
	return SecretValue{
		AddedAt:     d.AddedAt,
		AvailableTo: d.AvailableTo,
		Deleted:     d.Deleted,
		Hash:        d.Hash,
		Signature:   d.Signature,
		SignedBy:    d.SignedBy,
		Value:       d.Value,
	}
}

// ValueDataFromSecretValue converts SecretValue to ValueData
func ValueDataFromSecretValue(sv SecretValue) ValueData {
	return ValueData(sv)
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

// HeaderMarker is the constant marker line that precedes the vault header JSON.
const HeaderMarker = "# === VAULT HEADER ==="

// ValidateHeaderMarker checks if a header marker line is valid.
// Returns nil if the marker is valid, or an error if invalid.
func ValidateHeaderMarker(markerLine string) error {
	if markerLine != HeaderMarker {
		return fmt.Errorf("invalid vault header marker: %q (expected %q)", markerLine, HeaderMarker)
	}
	return nil
}

// HeaderMarkerForVersion returns the header marker (version-independent).
// Deprecated: The version parameter is ignored. Use HeaderMarker constant directly.
func HeaderMarkerForVersion(_ int) string {
	return HeaderMarker
}

// detectVersionFromJSON extracts the version from header JSON without full parsing.
// Uses a quick prefix check for efficiency.
func detectVersionFromJSON(data []byte) (int, error) {
	// Quick check for version at start of JSON
	// Format: {"version":N,...}
	const prefix = `{"version":`
	str := string(data)
	if len(str) < len(prefix)+1 {
		return 0, fmt.Errorf("header JSON too short")
	}

	if str[:len(prefix)] != prefix {
		return 0, fmt.Errorf("cannot detect version from header JSON")
	}

	// Extract digits after "version":
	rest := str[len(prefix):]
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

// ParseValueData extracts ValueData from an Entry
func ParseValueData(e *Entry) (*ValueData, error) {
	if e.Type != EntryTypeValue {
		return nil, fmt.Errorf("entry is not a value (type=%s)", e.Type)
	}
	var data ValueData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to parse value data: %w", err)
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
	data := ValueDataFromSecretValue(sv)
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
