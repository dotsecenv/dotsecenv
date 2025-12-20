package identity

import (
	"time"
)

// Identity represents a user/machine identity with its public GPG key.
// Identities are stored in vault files and used to control access to secrets.
type Identity struct {
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
