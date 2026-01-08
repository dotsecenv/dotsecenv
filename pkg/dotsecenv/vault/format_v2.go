package vault

import (
	"encoding/json"
	"fmt"
)

// HeaderV2Raw is the on-disk format for v2 headers.
// Identities are stored as a dict {fingerprint: line, ...}.
type HeaderV2Raw struct {
	Version    int                    `json:"version"`
	Identities map[string]int         `json:"identities"` // {fingerprint: line, ...}
	Secrets    map[string]SecretIndex `json:"secrets"`
}

// MarshalHeaderV2 creates the JSON representation of the header in v2 format.
// Identities are serialized as {fingerprint: line, ...} dict.
func MarshalHeaderV2(h *Header) ([]byte, error) {
	raw := HeaderV2Raw{
		Version:    2,
		Identities: h.Identities,
		Secrets:    h.Secrets,
	}

	// Ensure non-nil maps for consistent JSON output
	if raw.Identities == nil {
		raw.Identities = make(map[string]int)
	}
	if raw.Secrets == nil {
		raw.Secrets = make(map[string]SecretIndex)
	}

	return json.Marshal(raw)
}

// UnmarshalHeaderV2 parses v2 header JSON into a Header.
// Identities are already in map[string]int format.
func UnmarshalHeaderV2(data []byte) (*Header, error) {
	var raw HeaderV2Raw
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal v2 header: %w", err)
	}

	h := &Header{
		Version:    raw.Version,
		Identities: raw.Identities,
		Secrets:    raw.Secrets,
	}

	if h.Identities == nil {
		h.Identities = make(map[string]int)
	}
	if h.Secrets == nil {
		h.Secrets = make(map[string]SecretIndex)
	}

	return h, nil
}

// HeaderMarkerV2 is the header marker for v2 vaults.
const HeaderMarkerV2 = "# === VAULT HEADER v2 ==="
