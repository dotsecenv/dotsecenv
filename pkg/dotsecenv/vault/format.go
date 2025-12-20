package vault

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// FormatVersion is the current vault format version
const FormatVersion = 1

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

// MarshalHeader creates the JSON representation of the header
func MarshalHeader(h *Header) ([]byte, error) {
	// Create ordered representation for deterministic JSON output
	// Identities sorted by line number (order added), secrets sorted by key
	type orderedHeader struct {
		Version    int                    `json:"version"`
		Identities [][2]interface{}       `json:"identities"` // [[fingerprint, line], ...]
		Secrets    map[string]SecretIndex `json:"secrets"`
	}

	// Sort identities by line number (ascending = order added)
	type idEntry struct {
		fp   string
		line int
	}
	idEntries := make([]idEntry, 0, len(h.Identities))
	for fp, line := range h.Identities {
		idEntries = append(idEntries, idEntry{fp, line})
	}
	sort.Slice(idEntries, func(i, j int) bool {
		return idEntries[i].line < idEntries[j].line
	})

	identities := make([][2]interface{}, len(idEntries))
	for i, e := range idEntries {
		identities[i] = [2]interface{}{e.fp, e.line}
	}

	ordered := orderedHeader{
		Version:    h.Version,
		Identities: identities,
		Secrets:    h.Secrets,
	}

	return json.Marshal(ordered)
}

// UnmarshalHeader parses JSON into a Header
func UnmarshalHeader(data []byte) (*Header, error) {
	// Parse the ordered format with identities as [[fingerprint, line], ...]
	type orderedHeader struct {
		Version    int                    `json:"version"`
		Identities [][2]interface{}       `json:"identities"` // [[fingerprint, line], ...]
		Secrets    map[string]SecretIndex `json:"secrets"`
	}

	var oh orderedHeader
	if err := json.Unmarshal(data, &oh); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	h := &Header{
		Version:    oh.Version,
		Identities: make(map[string]int, len(oh.Identities)),
		Secrets:    oh.Secrets,
	}

	// Convert [[fingerprint, line], ...] back to map
	for _, pair := range oh.Identities {
		if len(pair) != 2 {
			return nil, fmt.Errorf("invalid identity entry: expected [fingerprint, line]")
		}
		fp, ok := pair[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid identity fingerprint: expected string")
		}
		lineFloat, ok := pair[1].(float64) // JSON numbers unmarshal as float64
		if !ok {
			return nil, fmt.Errorf("invalid identity line number: expected number")
		}
		h.Identities[fp] = int(lineFloat)
	}

	if h.Secrets == nil {
		h.Secrets = make(map[string]SecretIndex)
	}
	return h, nil
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
