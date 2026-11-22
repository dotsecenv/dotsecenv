package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// validate reports an edited identity through the shared identity verifier.
func TestValidateVaultData_UsesSharedVerification(t *testing.T) {
	v := vault.NewVault()
	v.Identities = []vault.Identity{{
		AddedAt:     time.Now().UTC(),
		Fingerprint: "FP1",
		SignedBy:    "FP1",
		PublicKey:   "cGs=",
		Hash:        "edited",
		Signature:   "aa",
	}}

	var messages []string
	for _, e := range validateVaultData(v, nil) {
		messages = append(messages, e.Message)
	}
	got := strings.Join(messages, "\n")
	if !strings.Contains(got, "hash mismatch") || !strings.Contains(got, "data tampering detected") {
		t.Fatalf("want the shared verifier's hash mismatch error, got:\n%s", got)
	}
}
