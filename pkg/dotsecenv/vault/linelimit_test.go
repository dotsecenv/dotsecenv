package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLargeValueRoundTrips(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault")
	big := strings.Repeat("A", 200*1024)
	now := time.Now().UTC()

	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatal(err)
	}
	if err := m.AddSecret(Secret{AddedAt: now, Key: "BIG", Values: []SecretValue{{AddedAt: now, Value: big}}}); err != nil {
		t.Fatal(err)
	}
	_ = m.Unlock()

	m = NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = m.Unlock() }()
	if s := m.GetSecretByKey("BIG"); s == nil || len(s.Values) != 1 || s.Values[0].Value != big {
		t.Fatal("large value did not round-trip through the Manager")
	}

	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	values, err := r.GetSecretValues("BIG")
	if err != nil || len(values) != 1 || values[0].Value != big {
		t.Fatalf("large value did not round-trip through the Reader: %v", err)
	}
	if err := r.StreamEntries(func(*Entry) error { return nil }); err != nil {
		t.Fatalf("StreamEntries: %v", err)
	}
}

func TestOverLimitValueIsRefused(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault")
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	huge := Secret{AddedAt: now, Key: "HUGE", Values: []SecretValue{{AddedAt: now, Value: strings.Repeat("A", MaxLineSize)}}}
	if err := w.AddSecretWithValues(huge); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want a too-large error, got %v", err)
	}
	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("vault changed after a refused write")
	}
}
