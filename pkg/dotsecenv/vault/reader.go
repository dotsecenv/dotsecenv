package vault

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// DataMarker separates the header from data entries
const DataMarker = "# === VAULT DATA ==="

// Reader provides efficient access to vault data using the header index
type Reader struct {
	path        string
	header      *Header
	version     int     // detected format version
	lineOffsets []int64 // byte offsets for each line (0-indexed)
}

// NewReader creates a new vault reader and parses the header
func NewReader(path string) (*Reader, error) {
	r := &Reader{path: path}
	if err := r.loadHeader(); err != nil {
		return nil, err
	}
	return r, nil
}

// loadHeader reads the vault file header and builds line offset index
func (r *Reader) loadHeader() error {
	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			// Empty vault
			r.header = NewHeader()
			r.version = LatestFormatVersion
			r.lineOffsets = nil
			return nil
		}
		return fmt.Errorf("failed to open vault: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Check if file is empty
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat vault: %w", err)
	}
	if info.Size() == 0 {
		r.header = NewHeader()
		r.version = LatestFormatVersion
		r.lineOffsets = nil
		return nil
	}

	// Build line offset index and parse header
	r.lineOffsets = make([]int64, 0, 100)
	scanner := bufio.NewScanner(file)
	var offset int64
	lineNum := 0
	var markerLine string
	var headerLine string

	for scanner.Scan() {
		line := scanner.Text()
		r.lineOffsets = append(r.lineOffsets, offset)

		switch lineNum {
		case 0:
			markerLine = line
		case 1:
			headerLine = line
		}

		// Account for newline character
		offset += int64(len(scanner.Bytes())) + 1
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan vault: %w", err)
	}

	if markerLine == "" || headerLine == "" {
		return fmt.Errorf("vault file missing valid header")
	}

	// Validate header marker
	if err := ValidateHeaderMarker(markerLine); err != nil {
		return fmt.Errorf("invalid vault file: %w", err)
	}

	// Detect version from JSON header
	version, err := detectVersionFromJSON([]byte(headerLine))
	if err != nil {
		return fmt.Errorf("failed to detect vault version: %w", err)
	}
	r.version = version

	// Validate version
	if version < MinSupportedVersion {
		return fmt.Errorf("vault format v%d is no longer supported (minimum: v%d)",
			version, MinSupportedVersion)
	}

	// Parse header using version-appropriate unmarshaler
	header, err := UnmarshalHeaderVersioned([]byte(headerLine), version)
	if err != nil {
		return fmt.Errorf("failed to parse vault header: %w", err)
	}
	r.header = header

	return nil
}

// Version returns the detected vault format version
func (r *Reader) Version() int {
	return r.version
}

// Header returns the vault header (read-only copy)
func (r *Reader) Header() Header {
	if r.header == nil {
		return Header{
			Version:    FormatVersion,
			Identities: make(map[string]int),
			Secrets:    make(map[string]SecretIndex),
		}
	}
	// Return a copy to prevent modification
	h := Header{
		Version:    r.header.Version,
		Identities: make(map[string]int, len(r.header.Identities)),
		Secrets:    make(map[string]SecretIndex, len(r.header.Secrets)),
	}
	for k, v := range r.header.Identities {
		h.Identities[k] = v
	}
	for k, v := range r.header.Secrets {
		valuesCopy := make([]int, len(v.Values))
		copy(valuesCopy, v.Values)
		h.Secrets[k] = SecretIndex{
			Definition: v.Definition,
			Values:     valuesCopy,
		}
	}
	return h
}

// ListIdentityFingerprints returns all identity fingerprints in the vault
func (r *Reader) ListIdentityFingerprints() []string {
	if r.header == nil {
		return nil
	}
	fingerprints := make([]string, 0, len(r.header.Identities))
	for fp := range r.header.Identities {
		fingerprints = append(fingerprints, fp)
	}
	return fingerprints
}

// ListSecretKeys returns all secret keys in the vault
func (r *Reader) ListSecretKeys() []string {
	if r.header == nil {
		return nil
	}
	keys := make([]string, 0, len(r.header.Secrets))
	for k := range r.header.Secrets {
		keys = append(keys, k)
	}
	return keys
}

// HasIdentity checks if an identity exists by fingerprint
func (r *Reader) HasIdentity(fingerprint string) bool {
	if r.header == nil {
		return false
	}
	_, exists := r.header.Identities[fingerprint]
	return exists
}

// HasSecret checks if a secret exists by key
func (r *Reader) HasSecret(key string) bool {
	if r.header == nil {
		return false
	}
	_, exists := r.header.Secrets[key]
	return exists
}

// readLine reads a specific line from the vault file (1-indexed)
func (r *Reader) readLine(lineNum int) (string, error) {
	if lineNum < 1 || lineNum > len(r.lineOffsets) {
		return "", fmt.Errorf("line %d out of range (1-%d)", lineNum, len(r.lineOffsets))
	}

	file, err := os.Open(r.path)
	if err != nil {
		return "", fmt.Errorf("failed to open vault: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Seek to line offset (convert to 0-indexed)
	offset := r.lineOffsets[lineNum-1]
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to seek to line %d: %w", lineNum, err)
	}

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read line %d: %w", lineNum, err)
		}
		return "", fmt.Errorf("unexpected EOF at line %d", lineNum)
	}

	return scanner.Text(), nil
}

// ReadEntry reads and parses an entry at a specific line (1-indexed)
func (r *Reader) ReadEntry(lineNum int) (*Entry, error) {
	line, err := r.readLine(lineNum)
	if err != nil {
		return nil, err
	}

	// Skip comment lines
	if strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("line %d is a comment, not an entry", lineNum)
	}

	return UnmarshalEntry([]byte(line))
}

// GetIdentity retrieves a specific identity by fingerprint
func (r *Reader) GetIdentity(fingerprint string) (*IdentityData, error) {
	if r.header == nil {
		return nil, fmt.Errorf("identity not found: %s", fingerprint)
	}

	lineNum, exists := r.header.Identities[fingerprint]
	if !exists {
		return nil, fmt.Errorf("identity not found: %s", fingerprint)
	}

	entry, err := r.ReadEntry(lineNum)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity at line %d: %w", lineNum, err)
	}

	return ParseIdentityData(entry)
}

// GetSecret retrieves a secret definition by key
func (r *Reader) GetSecret(key string) (*SecretData, error) {
	if r.header == nil {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	idx, exists := r.header.Secrets[key]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	entry, err := r.ReadEntry(idx.Definition)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret at line %d: %w", idx.Definition, err)
	}

	return ParseSecretData(entry)
}

// GetSecretValues retrieves all values for a secret
func (r *Reader) GetSecretValues(key string) ([]ValueData, error) {
	if r.header == nil {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	idx, exists := r.header.Secrets[key]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", key)
	}

	values := make([]ValueData, 0, len(idx.Values))
	for _, lineNum := range idx.Values {
		entry, err := r.ReadEntry(lineNum)
		if err != nil {
			return nil, fmt.Errorf("failed to read value at line %d: %w", lineNum, err)
		}

		data, err := ParseValueData(entry)
		if err != nil {
			return nil, err
		}
		values = append(values, *data)
	}

	return values, nil
}

// GetAllIdentities retrieves all identities from the vault
func (r *Reader) GetAllIdentities() ([]IdentityData, error) {
	if r.header == nil || len(r.header.Identities) == 0 {
		return nil, nil
	}

	identities := make([]IdentityData, 0, len(r.header.Identities))
	for fp := range r.header.Identities {
		id, err := r.GetIdentity(fp)
		if err != nil {
			return nil, err
		}
		identities = append(identities, *id)
	}

	return identities, nil
}

// StreamEntries iterates through all entries in the vault, calling the handler for each
func (r *Reader) StreamEntries(handler func(entry *Entry) error) error {
	file, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Empty vault
		}
		return fmt.Errorf("failed to open vault: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comment/header lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Skip the header JSON line (line 2)
		if lineNum == 2 {
			continue
		}

		entry, err := UnmarshalEntry([]byte(line))
		if err != nil {
			return fmt.Errorf("failed to parse entry at line %d: %w", lineNum, err)
		}

		if err := handler(entry); err != nil {
			return err
		}
	}

	return scanner.Err()
}

// TotalLines returns the total number of lines in the vault
func (r *Reader) TotalLines() int {
	return len(r.lineOffsets)
}

// EntryCount returns the count of data entries (excluding header lines)
func (r *Reader) EntryCount() int {
	if r.header == nil {
		return 0
	}

	count := len(r.header.Identities)
	for _, idx := range r.header.Secrets {
		count++ // secret definition
		count += len(idx.Values)
	}
	return count
}
