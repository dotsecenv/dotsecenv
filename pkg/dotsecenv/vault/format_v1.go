package vault

import (
	"encoding/json"
	"fmt"
	"sort"
)

// HeaderV1Raw is the on-disk format for v1 headers.
// Identities are stored as an array of [fingerprint, line] pairs.
type HeaderV1Raw struct {
	Version    int                    `json:"version"`
	Identities [][2]interface{}       `json:"identities"` // [[fingerprint, line], ...]
	Secrets    map[string]SecretIndex `json:"secrets"`
}

// MarshalHeaderV1 creates the JSON representation of the header in v1 format.
// Identities are serialized as [[fingerprint, line], ...] sorted by line number.
func MarshalHeaderV1(h *Header) ([]byte, error) {
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

	raw := HeaderV1Raw{
		Version:    1,
		Identities: identities,
		Secrets:    h.Secrets,
	}

	return json.Marshal(raw)
}

// UnmarshalHeaderV1 parses v1 header JSON into a Header.
// Converts [[fingerprint, line], ...] back to map[string]int.
func UnmarshalHeaderV1(data []byte) (*Header, error) {
	var raw HeaderV1Raw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal v1 header: %w", err)
	}

	h := &Header{
		Version:    raw.Version,
		Identities: make(map[string]int, len(raw.Identities)),
		Secrets:    raw.Secrets,
	}

	// Convert [[fingerprint, line], ...] back to map
	for _, pair := range raw.Identities {
		if len(pair) != 2 {
			return nil, fmt.Errorf("invalid v1 identity entry: expected [fingerprint, line]")
		}
		fp, ok := pair[0].(string)
		if !ok {
			return nil, fmt.Errorf("invalid v1 identity fingerprint: expected string")
		}
		lineFloat, ok := pair[1].(float64) // JSON numbers unmarshal as float64
		if !ok {
			return nil, fmt.Errorf("invalid v1 identity line number: expected number")
		}
		h.Identities[fp] = int(lineFloat)
	}

	if h.Secrets == nil {
		h.Secrets = make(map[string]SecretIndex)
	}

	return h, nil
}

// HeaderMarkerV1 is the header marker for v1 vaults.
const HeaderMarkerV1 = "# === VAULT HEADER v1 ==="
