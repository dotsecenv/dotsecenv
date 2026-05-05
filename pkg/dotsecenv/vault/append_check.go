package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

// MaxClockSkew is the maximum drift tolerated between a new entry's
// asserted added_at and the local clock at write time. Bounds:
//   - Lower: a new entry must not be older than the most recent existing
//     entry's added_at (rejects trivial backdating).
//   - Upper: a new entry must not be more than MaxClockSkew in the future
//     of the local clock (a forward-dated entry would block every
//     subsequent legitimate write until real time caught up).
//
// This is a write-time speed bump, not a cryptographic guarantee. A holder
// of a signing key can still hand-craft the JSONL with arbitrary
// timestamps; see concepts/threat-model on the website.
const MaxClockSkew = 5 * time.Minute

// addedAtOnly is a minimal shape for extracting added_at from any entry.
type addedAtOnly struct {
	AddedAt time.Time `json:"added_at"`
}

// maxAddedAt walks the data section (after the header markers) and
// returns the largest added_at found. Returns the zero time for an
// empty vault. Lines that fail to parse are skipped — stricter
// validators catch malformed lines elsewhere.
func (w *Writer) maxAddedAt() time.Time {
	var max time.Time
	// lines[0]=HeaderMarker, lines[1]=header JSON, lines[2]=DataMarker
	for i := 3; i < len(w.lines); i++ {
		line := w.lines[i]
		if line == "" {
			continue
		}
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		var d addedAtOnly
		if err := json.Unmarshal(entry.Data, &d); err != nil {
			continue
		}
		if d.AddedAt.After(max) {
			max = d.AddedAt
		}
	}
	return max
}

// checkAppendTimestamps enforces the bounds described on MaxClockSkew
// against every supplied added_at. Pass all new entries' timestamps for
// a multi-entry write (e.g., AddSecretWithValues).
func (w *Writer) checkAppendTimestamps(newAddedAts ...time.Time) error {
	max := w.maxAddedAt()
	now := time.Now().UTC()
	upper := now.Add(MaxClockSkew)
	for _, t := range newAddedAts {
		if t.Before(max) {
			return fmt.Errorf(
				"refusing to append entry: added_at (%s) is older than the most recent existing entry's added_at (%s); the vault must remain in monotonic time order. If your local clock is wrong, fix it and retry",
				t.UTC().Format(time.RFC3339),
				max.UTC().Format(time.RFC3339),
			)
		}
		if t.After(upper) {
			return fmt.Errorf(
				"refusing to append entry: added_at (%s) is more than %s in the future of the local clock (%s); a forward-dated entry would block subsequent legitimate writes",
				t.UTC().Format(time.RFC3339),
				MaxClockSkew,
				now.Format(time.RFC3339),
			)
		}
	}
	return nil
}
