package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/identity"
)

func setBinaryVersion(t *testing.T, v string) {
	t.Helper()
	old := BinaryVersion
	BinaryVersion = v
	t.Cleanup(func() { BinaryVersion = old })
}

// headerLine returns the header JSON line of the vault at path.
func headerLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		t.Fatalf("vault %s has no header line", path)
	}
	return lines[1]
}

func appendIdentity(t *testing.T, path, fp string) {
	t.Helper()
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddIdentity(identity.Identity{AddedAt: time.Now().UTC(), Fingerprint: fp}); err != nil {
		t.Fatalf("AddIdentity: %v", err)
	}
}

func rewrite(t *testing.T, path string) {
	t.Helper()
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := w.ReadVault()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.RewriteFromVault(v); err != nil {
		t.Fatalf("RewriteFromVault: %v", err)
	}
}

// stampOf returns the vault's stamp, checking that Writer and Reader agree.
func stampOf(t *testing.T, path string) string {
	t.Helper()
	w, err := NewWriterReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(path)
	if err != nil {
		t.Fatal(err)
	}
	if ws, rs := w.Header().DotsecenvVersion, r.Header().DotsecenvVersion; ws != rs {
		t.Fatalf("Writer stamp %q, Reader stamp %q", ws, rs)
	}
	return w.Header().DotsecenvVersion
}

func TestParseRelease(t *testing.T) {
	tests := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"0.11.0", [3]int{0, 11, 0}, true},
		{"v0.11.0", [3]int{0, 11, 0}, true},
		{"v0.11.0-3-gabc1234-dirty", [3]int{0, 11, 0}, true},
		{"1.2.3+build", [3]int{1, 2, 3}, true},
		{"v0", [3]int{}, false},
		{"v0-11-g5cafdcb", [3]int{}, false},
		{"5cafdcb", [3]int{}, false},
		{"unknown", [3]int{}, false},
		{"", [3]int{}, false},
		{"1.2", [3]int{}, false},
		{"1.2.3.4", [3]int{}, false},
		{"1..3", [3]int{}, false},
	}
	for _, tt := range tests {
		got, ok := parseRelease(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Errorf("parseRelease(%q) = %v, %v; want %v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestIsNewerRelease(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.12.0", "0.11.0", true},
		{"1.0.0", "0.99.99", true},
		{"0.11.1", "v0.11.0-3-gabc1234", true},
		{"0.11.0", "0.11.0", false},
		{"0.11.0", "0.12.0", false},
		{"0.12.0", "unknown", false},
		{"", "0.11.0", false},
		{"0.12.0", "", false},
	}
	for _, tt := range tests {
		if got := IsNewerRelease(tt.a, tt.b); got != tt.want {
			t.Errorf("IsNewerRelease(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestReleaseStamp_SetOnCreateAndRewriteOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")

	setBinaryVersion(t, "v0.11.0-3-gabc1234-dirty")
	if _, err := NewWriter(path); err != nil {
		t.Fatal(err)
	}
	if got := stampOf(t, path); got != "0.11.0" {
		t.Fatalf("stamp after create = %q, want 0.11.0", got)
	}

	// The Manager path is the one 'secret store' takes.
	BinaryVersion = "0.12.0"
	appendHistory(t, path, "SEC", history(SecretValue{AvailableTo: []string{"FP1"}, Value: "v1"})...)
	w, err := NewWriterReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.Header().Secrets["SEC"]; !ok {
		t.Fatal("secret was not appended")
	}
	if got := w.Header().DotsecenvVersion; got != "0.11.0" {
		t.Fatalf("stamp after append by 0.12.0 = %q, want 0.11.0", got)
	}

	rewrite(t, path)
	if got := stampOf(t, path); got != "0.12.0" {
		t.Fatalf("stamp after rewrite by 0.12.0 = %q, want 0.12.0", got)
	}

	BinaryVersion = "unknown"
	rewrite(t, path)
	if got := stampOf(t, path); got != "" {
		t.Fatalf("stamp after rewrite by an unknown build = %q, want none", got)
	}
}

func TestReleaseStamp_UnstampedHeaderUnchangedByAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")

	setBinaryVersion(t, "")
	appendIdentity(t, path, "FP1")
	before := headerLine(t, path)
	if strings.Contains(before, "dotsecenv_version") {
		t.Fatalf("unstamped vault header carries a stamp: %s", before)
	}

	BinaryVersion = "0.11.0"
	appendIdentity(t, path, "FP2")
	after := headerLine(t, path)
	if strings.Contains(after, "dotsecenv_version") {
		t.Fatalf("append stamped the header: %s", after)
	}
	if want := strings.Replace(before, `"identities":{"FP1":4}`, `"identities":{"FP1":4,"FP2":5}`, 1); after != want {
		t.Fatalf("header after append = %s, want %s", after, want)
	}
}
