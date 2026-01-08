package vault

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

// Writer handles append-only vault modifications with atomic header updates
type Writer struct {
	path     string
	header   *Header
	version  int      // current vault format version
	lines    []string // cached lines for header rewriting
	readOnly bool     // if true, don't try to create/modify files
}

// NewWriter creates a new vault writer
// If the file doesn't exist, it creates a new vault
// If it exists, it loads the current header
func NewWriter(path string) (*Writer, error) {
	return newWriter(path, false)
}

// NewWriterReadOnly creates a vault writer in read-only mode
// It will not create new vaults or temp files - only read existing data
func NewWriterReadOnly(path string) (*Writer, error) {
	return newWriter(path, true)
}

func newWriter(path string, readOnly bool) (*Writer, error) {
	w := &Writer{path: path, readOnly: readOnly}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if readOnly {
			return nil, fmt.Errorf("vault file does not exist: %s", path)
		}
		// Create new vault
		if err := w.createNewVault(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to stat vault file: %w", err)
	} else {
		// Load existing vault
		if err := w.loadExisting(); err != nil {
			return nil, err
		}
	}

	return w, nil
}

// createNewVault initializes a new vault file with the latest format version
func (w *Writer) createNewVault() error {
	// Ensure directory exists
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	w.header = NewHeader()
	w.version = LatestFormatVersion
	w.lines = []string{
		HeaderMarker,
		"", // placeholder for header JSON
		DataMarker,
	}

	return w.flush()
}

// loadExisting loads an existing vault's header and lines
func (w *Writer) loadExisting() error {
	file, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("failed to open vault: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Check if file is empty
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat vault: %w", err)
	}
	if info.Size() == 0 {
		if w.readOnly {
			// In read-only mode, treat empty file as empty vault (no write needed)
			w.header = NewHeader()
			w.version = LatestFormatVersion
			w.lines = []string{
				HeaderMarker,
				"", // will be populated if we ever need to read
				DataMarker,
			}
			return nil
		}
		// Treat empty file as new vault
		return w.createNewVault()
	}

	scanner := bufio.NewScanner(file)
	w.lines = make([]string, 0, 100)
	lineNum := 0
	var markerLine string
	var headerLine string

	for scanner.Scan() {
		line := scanner.Text()
		w.lines = append(w.lines, line)

		switch lineNum {
		case 0:
			markerLine = line
		case 1:
			headerLine = line
		}
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to scan vault: %w", err)
	}

	if lineNum < 3 {
		if w.readOnly {
			// In read-only mode, treat malformed file as empty vault
			w.header = NewHeader()
			w.version = LatestFormatVersion
			w.lines = []string{
				HeaderMarker,
				"",
				DataMarker,
			}
			return nil
		}
		// File exists but is malformed, recreate it
		return w.createNewVault()
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
	w.version = version

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
	w.header = header

	return nil
}

// flush writes all lines to the vault file atomically
func (w *Writer) flush() error {
	// Update header line using current version's format
	headerJSON, err := MarshalHeaderVersioned(w.header, w.version)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	w.lines[1] = string(headerJSON)

	// Write to temp file first for atomicity
	tmpPath := w.path + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	writer := bufio.NewWriter(tmpFile)
	for i, line := range w.lines {
		if _, err := writer.WriteString(line); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to write line %d: %w", i, err)
		}
		if _, err := writer.WriteString("\n"); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("failed to write newline at line %d: %w", i, err)
		}
	}

	if err := writer.Flush(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, w.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// nextLineNumber returns the next available line number (1-indexed)
func (w *Writer) nextLineNumber() int {
	return len(w.lines) + 1
}

// AddIdentity adds a new identity to the vault
func (w *Writer) AddIdentity(id identity.Identity) error {
	// Check for duplicate
	if _, exists := w.header.Identities[id.Fingerprint]; exists {
		return fmt.Errorf("skipped, already present: %s", id.Fingerprint)
	}

	lineNum := w.nextLineNumber()

	entry, err := CreateIdentityEntry(id)
	if err != nil {
		return err
	}

	entryJSON, err := MarshalEntry(*entry)
	if err != nil {
		return fmt.Errorf("failed to marshal identity entry: %w", err)
	}

	// Append entry and update header
	w.lines = append(w.lines, string(entryJSON))
	w.header.Identities[id.Fingerprint] = lineNum

	return w.flush()
}

// AddSecret adds a new secret definition to the vault
func (w *Writer) AddSecret(s Secret) error {
	// Check for duplicate (case-insensitive)
	for existingKey := range w.header.Secrets {
		if CompareSecretKeys(existingKey, s.Key) {
			return fmt.Errorf("secret already exists: %s", existingKey)
		}
	}

	lineNum := w.nextLineNumber()

	entry, err := CreateSecretEntry(s)
	if err != nil {
		return err
	}

	entryJSON, err := MarshalEntry(*entry)
	if err != nil {
		return fmt.Errorf("failed to marshal secret entry: %w", err)
	}

	// Append entry and update header
	w.lines = append(w.lines, string(entryJSON))
	w.header.Secrets[s.Key] = SecretIndex{
		Definition: lineNum,
		Values:     []int{},
	}

	return w.flush()
}

// AddSecretValue adds a new value to an existing secret
func (w *Writer) AddSecretValue(secretKey string, sv SecretValue) error {
	// Find secret by case-insensitive comparison
	var idx SecretIndex
	var foundKey string
	found := false
	for existingKey, existingIdx := range w.header.Secrets {
		if CompareSecretKeys(existingKey, secretKey) {
			idx = existingIdx
			foundKey = existingKey
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("secret not found: %s", secretKey)
	}

	lineNum := w.nextLineNumber()

	entry, err := CreateValueEntry(secretKey, sv)
	if err != nil {
		return err
	}

	entryJSON, err := MarshalEntry(*entry)
	if err != nil {
		return fmt.Errorf("failed to marshal value entry: %w", err)
	}

	// Append entry and update header
	w.lines = append(w.lines, string(entryJSON))
	idx.Values = append(idx.Values, lineNum)
	w.header.Secrets[foundKey] = idx

	return w.flush()
}

// AddSecretWithValues adds a secret definition and its initial values
func (w *Writer) AddSecretWithValues(s Secret) error {
	// Check for duplicate (case-insensitive)
	for existingKey := range w.header.Secrets {
		if CompareSecretKeys(existingKey, s.Key) {
			return fmt.Errorf("secret already exists: %s", existingKey)
		}
	}

	// Add secret definition
	defLineNum := w.nextLineNumber()

	defEntry, err := CreateSecretEntry(s)
	if err != nil {
		return err
	}

	defEntryJSON, err := MarshalEntry(*defEntry)
	if err != nil {
		return fmt.Errorf("failed to marshal secret entry: %w", err)
	}

	w.lines = append(w.lines, string(defEntryJSON))

	// Add values
	valueLines := make([]int, 0, len(s.Values))
	for _, sv := range s.Values {
		valLineNum := w.nextLineNumber()

		valEntry, err := CreateValueEntry(s.Key, sv)
		if err != nil {
			return err
		}

		valEntryJSON, err := MarshalEntry(*valEntry)
		if err != nil {
			return fmt.Errorf("failed to marshal value entry: %w", err)
		}

		w.lines = append(w.lines, string(valEntryJSON))
		valueLines = append(valueLines, valLineNum)
	}

	// Update header
	w.header.Secrets[s.Key] = SecretIndex{
		Definition: defLineNum,
		Values:     valueLines,
	}

	return w.flush()
}

// Version returns the current vault format version
func (w *Writer) Version() int {
	return w.version
}

// Header returns a copy of the current header
func (w *Writer) Header() Header {
	if w.header == nil {
		return Header{
			Version:    FormatVersion,
			Identities: make(map[string]int),
			Secrets:    make(map[string]SecretIndex),
		}
	}
	h := Header{
		Version:    w.header.Version,
		Identities: make(map[string]int, len(w.header.Identities)),
		Secrets:    make(map[string]SecretIndex, len(w.header.Secrets)),
	}
	for k, v := range w.header.Identities {
		h.Identities[k] = v
	}
	for k, v := range w.header.Secrets {
		valuesCopy := make([]int, len(v.Values))
		copy(valuesCopy, v.Values)
		h.Secrets[k] = SecretIndex{
			Definition: v.Definition,
			Values:     valuesCopy,
		}
	}
	return h
}

// TotalLines returns the current number of lines
func (w *Writer) TotalLines() int {
	return len(w.lines)
}

// Path returns the vault file path
func (w *Writer) Path() string {
	return w.path
}

// RewriteFromVault completely rewrites the vault file from a Vault struct
// using the latest format version. This is used for defragmentation.
func (w *Writer) RewriteFromVault(v Vault) error {
	return w.RewriteFromVaultWithVersion(v, LatestFormatVersion)
}

// RewriteFromVaultWithVersion completely rewrites the vault file from a Vault struct
// using the specified format version. This is used for upgrades and defragmentation.
func (w *Writer) RewriteFromVaultWithVersion(v Vault, version int) error {
	// Start fresh with specified version
	w.header = NewHeader()
	w.version = version
	w.lines = []string{
		HeaderMarker,
		"", // placeholder for header JSON
		DataMarker,
	}

	// Add identities
	for _, id := range v.Identities {
		lineNum := w.nextLineNumber()

		entry, err := CreateIdentityEntry(id)
		if err != nil {
			return err
		}

		entryJSON, err := MarshalEntry(*entry)
		if err != nil {
			return fmt.Errorf("failed to marshal identity entry: %w", err)
		}

		w.lines = append(w.lines, string(entryJSON))
		w.header.Identities[id.Fingerprint] = lineNum
	}

	// Add secrets with their values consecutively
	for _, s := range v.Secrets {
		defLineNum := w.nextLineNumber()

		defEntry, err := CreateSecretEntry(s)
		if err != nil {
			return err
		}

		defEntryJSON, err := MarshalEntry(*defEntry)
		if err != nil {
			return fmt.Errorf("failed to marshal secret entry: %w", err)
		}

		w.lines = append(w.lines, string(defEntryJSON))

		valueLines := make([]int, 0, len(s.Values))
		for _, sv := range s.Values {
			valLineNum := w.nextLineNumber()

			valEntry, err := CreateValueEntry(s.Key, sv)
			if err != nil {
				return err
			}

			valEntryJSON, err := MarshalEntry(*valEntry)
			if err != nil {
				return fmt.Errorf("failed to marshal value entry: %w", err)
			}

			w.lines = append(w.lines, string(valEntryJSON))
			valueLines = append(valueLines, valLineNum)
		}

		w.header.Secrets[s.Key] = SecretIndex{
			Definition: defLineNum,
			Values:     valueLines,
		}
	}

	return w.flush()
}

// ReadVault reconstructs the full Vault struct from the file
func (w *Writer) ReadVault() (Vault, error) {
	v := NewVault()

	// Collect identities with their line numbers for sorting
	type idWithLine struct {
		lineNum int
		fp      string
	}
	idLines := make([]idWithLine, 0, len(w.header.Identities))
	for fp, lineNum := range w.header.Identities {
		idLines = append(idLines, idWithLine{lineNum: lineNum, fp: fp})
	}
	// Sort by line number to preserve chronological order
	sort.Slice(idLines, func(i, j int) bool {
		return idLines[i].lineNum < idLines[j].lineNum
	})

	// Read identities in chronological order
	for _, idl := range idLines {
		if idl.lineNum < 1 || idl.lineNum > len(w.lines) {
			return v, fmt.Errorf("invalid line number %d for identity %s", idl.lineNum, idl.fp)
		}

		line := w.lines[idl.lineNum-1]
		entry, err := UnmarshalEntry([]byte(line))
		if err != nil {
			return v, fmt.Errorf("failed to parse identity entry at line %d: %w", idl.lineNum, err)
		}

		data, err := ParseIdentityData(entry)
		if err != nil {
			return v, err
		}

		v.Identities = append(v.Identities, data.ToIdentity())
	}

	// Collect secrets with their line numbers for sorting
	type secretWithLine struct {
		key     string
		idx     SecretIndex
		defLine int
	}
	secretLines := make([]secretWithLine, 0, len(w.header.Secrets))
	for key, idx := range w.header.Secrets {
		secretLines = append(secretLines, secretWithLine{key: key, idx: idx, defLine: idx.Definition})
	}
	// Sort by definition line number to preserve chronological order
	sort.Slice(secretLines, func(i, j int) bool {
		return secretLines[i].defLine < secretLines[j].defLine
	})

	// Read secrets in chronological order
	for _, sl := range secretLines {
		if sl.defLine < 1 || sl.defLine > len(w.lines) {
			return v, fmt.Errorf("invalid line number %d for secret %s", sl.defLine, sl.key)
		}

		secretLine := w.lines[sl.defLine-1]
		secretEntry, err := UnmarshalEntry([]byte(secretLine))
		if err != nil {
			return v, fmt.Errorf("failed to parse secret entry at line %d: %w", sl.defLine, err)
		}

		secretData, err := ParseSecretData(secretEntry)
		if err != nil {
			return v, err
		}

		secret := Secret{
			AddedAt:   secretData.AddedAt,
			Hash:      secretData.Hash,
			Key:       secretData.Key,
			Signature: secretData.Signature,
			SignedBy:  secretData.SignedBy,
			Values:    make([]SecretValue, 0, len(sl.idx.Values)),
		}

		// Read values (already in chronological order from the header's Values array)
		for _, valLineNum := range sl.idx.Values {
			if valLineNum < 1 || valLineNum > len(w.lines) {
				return v, fmt.Errorf("invalid line number %d for value of secret %s", valLineNum, sl.key)
			}

			valLine := w.lines[valLineNum-1]
			valEntry, err := UnmarshalEntry([]byte(valLine))
			if err != nil {
				return v, fmt.Errorf("failed to parse value entry at line %d: %w", valLineNum, err)
			}

			valData, err := ParseValueData(valEntry)
			if err != nil {
				return v, err
			}

			secret.Values = append(secret.Values, valData.ToSecretValue())
		}

		v.Secrets = append(v.Secrets, secret)
	}

	return v, nil
}

// GetLine returns a specific line (1-indexed)
func (w *Writer) GetLine(lineNum int) (string, error) {
	if lineNum < 1 || lineNum > len(w.lines) {
		return "", fmt.Errorf("line %d out of range (1-%d)", lineNum, len(w.lines))
	}
	return w.lines[lineNum-1], nil
}

// UpdateHeader updates only the header without modifying data entries
// Used when the header needs to be refreshed (e.g., after external modification)
func (w *Writer) UpdateHeader(h *Header) error {
	w.header = h
	return w.flush()
}

// Reload reloads the vault from disk
func (w *Writer) Reload() error {
	return w.loadExisting()
}

// IsEmpty returns true if the vault has no entries
func (w *Writer) IsEmpty() bool {
	return w.header == nil ||
		(len(w.header.Identities) == 0 && len(w.header.Secrets) == 0)
}

// String returns a string representation of the vault for debugging
func (w *Writer) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Vault: %s\n", w.path))
	sb.WriteString(fmt.Sprintf("  Identities: %d\n", len(w.header.Identities)))
	sb.WriteString(fmt.Sprintf("  Secrets: %d\n", len(w.header.Secrets)))
	sb.WriteString(fmt.Sprintf("  Total lines: %d\n", len(w.lines)))
	return sb.String()
}
