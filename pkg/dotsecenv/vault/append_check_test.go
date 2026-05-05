package vault

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

func newWriterForTest(t *testing.T) *Writer {
	t.Helper()
	w, err := NewWriter(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}
	return w
}

func TestCheckAppendTimestamps_EmptyVaultAcceptsAnyNonFutureTime(t *testing.T) {
	w := newWriterForTest(t)
	now := time.Now().UTC()
	if err := w.checkAppendTimestamps(now); err != nil {
		t.Fatalf("expected empty vault to accept now, got: %v", err)
	}
	// Far past also fine — no existing entries to compare against.
	if err := w.checkAppendTimestamps(now.Add(-365 * 24 * time.Hour)); err != nil {
		t.Fatalf("expected empty vault to accept past timestamps, got: %v", err)
	}
}

func TestAddIdentity_RejectsBackdated(t *testing.T) {
	w := newWriterForTest(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("first AddIdentity failed: %v", err)
	}

	err := w.AddIdentity(identity.Identity{AddedAt: now.Add(-1 * time.Hour), Fingerprint: "FP2"})
	if err == nil {
		t.Fatal("expected backdated AddIdentity to be rejected")
	}
	if !strings.Contains(err.Error(), "older than the most recent existing entry") {
		t.Errorf("expected backdating error, got: %v", err)
	}
}

func TestAddIdentity_AcceptsEqualOrLater(t *testing.T) {
	w := newWriterForTest(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("first AddIdentity failed: %v", err)
	}
	// Equal added_at must succeed (two writes inside one second).
	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP2"}); err != nil {
		t.Errorf("equal-time AddIdentity rejected: %v", err)
	}
	// Later timestamp must succeed.
	if err := w.AddIdentity(identity.Identity{AddedAt: now.Add(time.Second), Fingerprint: "FP3"}); err != nil {
		t.Errorf("later AddIdentity rejected: %v", err)
	}
}

func TestAddIdentity_RejectsForwardDatedBeyondSkew(t *testing.T) {
	w := newWriterForTest(t)
	tooFarFuture := time.Now().UTC().Add(MaxClockSkew + time.Minute)
	err := w.AddIdentity(identity.Identity{AddedAt: tooFarFuture, Fingerprint: "FP1"})
	if err == nil {
		t.Fatal("expected forward-dated AddIdentity to be rejected")
	}
	if !strings.Contains(err.Error(), "in the future") {
		t.Errorf("expected forward-dating error, got: %v", err)
	}
}

func TestAddIdentity_AcceptsForwardDatedWithinSkew(t *testing.T) {
	w := newWriterForTest(t)
	withinSkew := time.Now().UTC().Add(MaxClockSkew - time.Minute)
	if err := w.AddIdentity(identity.Identity{AddedAt: withinSkew, Fingerprint: "FP1"}); err != nil {
		t.Errorf("within-skew AddIdentity rejected: %v", err)
	}
}

func TestAddSecret_RejectsBackdated(t *testing.T) {
	w := newWriterForTest(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	err := w.AddSecret(Secret{AddedAt: now.Add(-time.Hour), Key: "OLD_SECRET"})
	if err == nil {
		t.Fatal("expected backdated AddSecret to be rejected")
	}
	if !strings.Contains(err.Error(), "older than the most recent") {
		t.Errorf("expected backdating error, got: %v", err)
	}
}

func TestAddSecretValue_RejectsBackdated(t *testing.T) {
	w := newWriterForTest(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}
	if err := w.AddSecret(Secret{AddedAt: now, Key: "MY_SECRET"}); err != nil {
		t.Fatalf("AddSecret failed: %v", err)
	}

	err := w.AddSecretValue("MY_SECRET", SecretValue{
		AddedAt:     now.Add(-time.Hour),
		AvailableTo: []string{"FP1"},
		Value:       "dGVzdA==",
	})
	if err == nil {
		t.Fatal("expected backdated AddSecretValue to be rejected")
	}
}

func TestAddSecretWithValues_RejectsAnyBackdatedTimestamp(t *testing.T) {
	w := newWriterForTest(t)
	now := time.Now().UTC().Truncate(time.Second)

	if err := w.AddIdentity(identity.Identity{AddedAt: now, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("AddIdentity failed: %v", err)
	}

	// Secret AddedAt is fine, but one value is backdated — must be rejected.
	err := w.AddSecretWithValues(Secret{
		AddedAt: now.Add(time.Second),
		Key:     "MIXED_TIMES",
		Values: []SecretValue{
			{AddedAt: now.Add(-time.Hour), AvailableTo: []string{"FP1"}, Value: "dGVzdA=="},
		},
	})
	if err == nil {
		t.Fatal("expected AddSecretWithValues to reject a backdated nested value")
	}
	if !strings.Contains(err.Error(), "older than the most recent") {
		t.Errorf("expected backdating error, got: %v", err)
	}
}

func TestMaxAddedAt_ReportsLatestAcrossAllEntries(t *testing.T) {
	w := newWriterForTest(t)
	t1 := time.Now().UTC().Truncate(time.Second)
	t2 := t1.Add(time.Second)
	t3 := t2.Add(time.Second)

	if err := w.AddIdentity(identity.Identity{AddedAt: t1, Fingerprint: "FP1"}); err != nil {
		t.Fatalf("AddIdentity FP1 failed: %v", err)
	}
	if err := w.AddIdentity(identity.Identity{AddedAt: t3, Fingerprint: "FP2"}); err != nil {
		t.Fatalf("AddIdentity FP2 failed: %v", err)
	}
	if err := w.AddSecret(Secret{AddedAt: t2, Key: "MID_TIME"}); err == nil {
		t.Error("expected AddSecret with t2 to fail because t3 already exists")
	}

	got := w.maxAddedAt()
	if !got.Equal(t3) {
		t.Errorf("maxAddedAt = %v, want %v", got, t3)
	}
}
