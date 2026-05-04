package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
)

// fakeFileInfo lets tests inject FileInfo without owning real root files.
type fakeFileInfo struct {
	name string
	mode os.FileMode
	uid  uint32
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64        { return 0 }
func (f *fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f *fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f *fakeFileInfo) IsDir() bool        { return false }
func (f *fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// secureStat returns a stat function that defers existence checks to os.Stat
// but overrides Mode and Uid in the returned FileInfo. Use uid=0 for tests
// that should pass the permission check; use uid != 0 to test rejection.
// Nonexistent paths return os.ErrNotExist (so loadFromDir's "missing dir"
// branch is exercised correctly).
func secureStat(uid uint32) func(string) (os.FileInfo, error) {
	return func(name string) (os.FileInfo, error) {
		real, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		return &fakeFileInfo{name: real.Name(), mode: 0o644, uid: uid}, nil
	}
}

// modeStat returns a stat function with a configurable mode.
func modeStat(mode os.FileMode) func(string) (os.FileInfo, error) {
	return func(name string) (os.FileInfo, error) {
		real, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		return &fakeFileInfo{name: real.Name(), mode: mode, uid: 0}, nil
	}
}

func writeFragment(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// --- loadFromDir tests ---

func TestLoadFromDir_MissingDir(t *testing.T) {
	pol, warnings, err := loadFromDir("/this/path/does/not/exist", secureStat(0))
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got: %v", err)
	}
	if !pol.Empty() {
		t.Errorf("expected empty policy for missing dir, got %d fragments", len(pol.Fragments))
	}
	if warnings != nil {
		t.Errorf("expected nil warnings, got: %v", warnings)
	}
}

func TestLoadFromDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	pol, warnings, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if !pol.Empty() {
		t.Errorf("expected empty policy for empty dir, got %d fragments", len(pol.Fragments))
	}
	if warnings != nil {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if pol.Dir != dir {
		t.Errorf("expected Dir=%s, got %s", dir, pol.Dir)
	}
}

func TestLoadFromDir_SingleValidFragment(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00-base.yaml", `
approved_algorithms:
  - algo: ECC
    curves: [P-384]
    min_bits: 384
`)

	pol, _, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if len(pol.Fragments) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(pol.Fragments))
	}
	f := pol.Fragments[0]
	if !strings.HasSuffix(f.Path, "00-base.yaml") {
		t.Errorf("unexpected path: %s", f.Path)
	}
	if len(f.ApprovedAlgorithms) != 1 || f.ApprovedAlgorithms[0].Algo != "ECC" {
		t.Errorf("approved_algorithms not parsed: %+v", f.ApprovedAlgorithms)
	}
}

func TestLoadFromDir_LexicalOrder(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "99-last.yaml", `approved_algorithms: [{algo: ECC, curves: [P-384], min_bits: 384}]`)
	writeFragment(t, dir, "00-first.yaml", `approved_algorithms: [{algo: RSA, min_bits: 2048}]`)
	writeFragment(t, dir, "50-middle.yaml", `approved_algorithms: [{algo: EdDSA, curves: [Ed25519], min_bits: 255}]`)

	pol, _, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if len(pol.Fragments) != 3 {
		t.Fatalf("expected 3 fragments, got %d", len(pol.Fragments))
	}
	want := []string{"00-first.yaml", "50-middle.yaml", "99-last.yaml"}
	for i, f := range pol.Fragments {
		if !strings.HasSuffix(f.Path, want[i]) {
			t.Errorf("fragment[%d]: expected suffix %s, got %s", i, want[i], f.Path)
		}
	}
}

func TestLoadFromDir_NonYamlFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "policy.yaml", `approved_algorithms: [{algo: RSA, min_bits: 2048}]`)
	writeFragment(t, dir, "README.md", `# notes`)
	writeFragment(t, dir, "policy.json", `{}`)

	pol, _, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if len(pol.Fragments) != 1 {
		t.Errorf("expected 1 fragment (only .yaml), got %d", len(pol.Fragments))
	}
}

func TestLoadFromDir_ForbiddenKey(t *testing.T) {
	// `behavior` and `gpg` were forbidden in PR #1 but became legitimate
	// policy keys in PR #3; only `login` and `vault` remain forbidden.
	cases := []struct {
		key  string
		body string
	}{
		{"login", "login:\n  fingerprint: ABCD\n"},
		{"vault", "vault:\n  - /tmp/v\n"},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			dir := t.TempDir()
			writeFragment(t, dir, "00-bad.yaml", tc.body)

			_, _, err := loadFromDir(dir, secureStat(0))
			if err == nil {
				t.Fatalf("expected error for forbidden key %q, got nil", tc.key)
			}
			if !errors.Is(err, ErrForbiddenKey) {
				t.Errorf("expected ErrForbiddenKey, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("error should cite forbidden key %q, got: %v", tc.key, err)
			}
			if !strings.Contains(err.Error(), "00-bad.yaml") {
				t.Errorf("error should cite fragment path, got: %v", err)
			}
		})
	}
}

// TestLoadFromDir_BehaviorAndGPGAccepted proves PR #3 lifted these keys
// from the forbidden list — they're now valid policy fields.
func TestLoadFromDir_BehaviorAndGPGAccepted(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00.yaml", `
behavior:
  restrict_to_configured_vaults: true
gpg:
  program: /usr/bin/gpg
`)
	pol, _, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if len(pol.Fragments) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(pol.Fragments))
	}
	f := pol.Fragments[0]
	if f.Behavior.RestrictToConfiguredVaults == nil || !*f.Behavior.RestrictToConfiguredVaults {
		t.Errorf("expected RestrictToConfiguredVaults=&true, got %v", f.Behavior.RestrictToConfiguredVaults)
	}
	if f.GPG.Program != "/usr/bin/gpg" {
		t.Errorf("expected GPG.Program=/usr/bin/gpg, got %q", f.GPG.Program)
	}
}

func TestLoadFromDir_EmptyAllowList(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00-empty.yaml", `approved_algorithms: []`)

	_, _, err := loadFromDir(dir, secureStat(0))
	if err == nil {
		t.Fatal("expected error for empty allow-list, got nil")
	}
	if !errors.Is(err, ErrEmptyAllowList) {
		t.Errorf("expected ErrEmptyAllowList, got: %v", err)
	}
	if !strings.Contains(err.Error(), "00-empty.yaml") {
		t.Errorf("error should cite fragment path, got: %v", err)
	}
}

func TestLoadFromDir_OmittedFieldIsFine(t *testing.T) {
	// A fragment that omits approved_algorithms entirely is valid (no opinion
	// on that dimension). Distinct from approved_algorithms: [] which is rejected.
	dir := t.TempDir()
	writeFragment(t, dir, "00-empty-doc.yaml", `# nothing here`)

	pol, _, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if len(pol.Fragments) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(pol.Fragments))
	}
	if pol.Fragments[0].ApprovedAlgorithms != nil {
		t.Errorf("expected nil ApprovedAlgorithms for omitted field, got %v", pol.Fragments[0].ApprovedAlgorithms)
	}
}

func TestLoadFromDir_InsecureMode(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00.yaml", `approved_algorithms: [{algo: RSA, min_bits: 2048}]`)

	_, _, err := loadFromDir(dir, modeStat(0o666))
	if err == nil {
		t.Fatal("expected error for mode 0666, got nil")
	}
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("expected ErrInsecurePermissions, got: %v", err)
	}
}

func TestLoadFromDir_InsecureOwner(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00.yaml", `approved_algorithms: [{algo: RSA, min_bits: 2048}]`)

	_, _, err := loadFromDir(dir, secureStat(1000))
	if err == nil {
		t.Fatal("expected error for non-root owner, got nil")
	}
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("expected ErrInsecurePermissions, got: %v", err)
	}
	if !strings.Contains(err.Error(), "uid=1000") {
		t.Errorf("error should cite uid, got: %v", err)
	}
}

func TestLoadFromDir_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00-bad.yaml", "approved_algorithms: [unclosed")

	_, _, err := loadFromDir(dir, secureStat(0))
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
	if !errors.Is(err, ErrMalformedFragment) {
		t.Errorf("expected ErrMalformedFragment, got: %v", err)
	}
	if !strings.Contains(err.Error(), "00-bad.yaml") {
		t.Errorf("error should cite fragment path, got: %v", err)
	}
}

// TestLoadFromDir_UnreadableFragment guards the "fail closed when a fragment
// is in the directory listing but cannot be read" case. statFn fakes secure
// permissions (so checkSecure passes), but the file's actual mode 0000
// causes os.ReadFile to fail. Skipped when running as root (root bypasses
// POSIX read bits).
func TestLoadFromDir_UnreadableFragment(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — POSIX read bits are bypassed; cannot exercise unreadable fragment path")
	}

	dir := t.TempDir()
	p := writeFragment(t, dir, "00.yaml", "approved_algorithms: [{algo: RSA, min_bits: 2048}]")
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatalf("chmod 0000: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

	_, _, err := loadFromDir(dir, secureStat(0))
	if err == nil {
		t.Fatal("expected error for unreadable fragment, got nil")
	}
	if !errors.Is(err, ErrUnreadableFragment) {
		t.Errorf("expected ErrUnreadableFragment, got: %v", err)
	}
	if !strings.Contains(err.Error(), "00.yaml") {
		t.Errorf("error should cite fragment path, got: %v", err)
	}
}

// --- MergedApprovedAlgorithms tests ---

func TestMerged_EmptyPolicy(t *testing.T) {
	p := Policy{}
	entries, origins := p.MergedApprovedAlgorithms()
	if entries != nil || origins != nil {
		t.Errorf("expected nil entries and origins for empty policy")
	}
}

func TestMerged_SingleFragment_Passthrough(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		}},
	}}
	entries, origins := p.MergedApprovedAlgorithms()
	if len(entries) != 1 || entries[0].Algo != "RSA" || entries[0].MinBits != 2048 {
		t.Errorf("unexpected entries: %+v", entries)
	}
	if len(origins) != 1 || len(origins[0]) != 1 || origins[0][0] != "00.yaml" {
		t.Errorf("unexpected origins: %+v", origins)
	}
}

func TestMerged_TwoFragments_DifferentAlgos_Union(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		}},
		{Path: "99.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-384"}, MinBits: 384},
		}},
	}}
	entries, _ := p.MergedApprovedAlgorithms()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (union), got %d", len(entries))
	}
}

func TestMerged_SameAlgo_CurvesUnion_MinBitsMin(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-384"}, MinBits: 384},
		}},
		{Path: "99.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-256", "P-521"}, MinBits: 256},
		}},
	}}
	entries, origins := p.MergedApprovedAlgorithms()
	if len(entries) != 1 {
		t.Fatalf("expected 1 collapsed entry, got %d", len(entries))
	}
	got := entries[0]
	if got.Algo != "ECC" {
		t.Errorf("expected ECC, got %s", got.Algo)
	}
	if got.MinBits != 256 {
		t.Errorf("expected MinBits=256 (min), got %d", got.MinBits)
	}
	wantCurves := []string{"P-256", "P-384", "P-521"}
	if len(got.Curves) != len(wantCurves) {
		t.Fatalf("expected %d curves, got %d: %v", len(wantCurves), len(got.Curves), got.Curves)
	}
	for i, c := range wantCurves {
		if got.Curves[i] != c {
			t.Errorf("curves[%d]: expected %s, got %s", i, c, got.Curves[i])
		}
	}
	if len(origins) != 1 || len(origins[0]) != 2 {
		t.Errorf("expected 2 origins for collapsed entry, got %v", origins)
	}
}

func TestMerged_OriginDedupe(t *testing.T) {
	// One fragment contributes two RSA entries (unusual but legal).
	// Origins should not list the fragment twice.
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 4096},
			{Algo: "RSA", MinBits: 2048},
		}},
	}}
	entries, origins := p.MergedApprovedAlgorithms()
	if len(entries) != 1 || entries[0].MinBits != 2048 {
		t.Errorf("expected collapsed RSA min_bits=2048, got: %+v", entries)
	}
	if len(origins) != 1 || len(origins[0]) != 1 {
		t.Errorf("expected origin list of length 1 (deduped), got: %v", origins)
	}
}

// --- Apply tests ---

func TestApply_EmptyPolicy_NoChange(t *testing.T) {
	cfg := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
	}
	out, warnings := Apply(cfg, Policy{})
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got: %v", warnings)
	}
	if len(out.ApprovedAlgorithms) != 1 || out.ApprovedAlgorithms[0].Algo != "RSA" {
		t.Errorf("config should be unchanged: %+v", out)
	}
}

func TestApply_PolicyRaisesMinBits(t *testing.T) {
	cfg := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		},
	}
	pol := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 4096},
		}},
	}}
	out, warnings := Apply(cfg, pol)
	if len(out.ApprovedAlgorithms) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(out.ApprovedAlgorithms))
	}
	if out.ApprovedAlgorithms[0].MinBits != 4096 {
		t.Errorf("expected MinBits raised to 4096, got %d", out.ApprovedAlgorithms[0].MinBits)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "raises min_bits for RSA") {
		t.Errorf("expected min_bits raise warning, got: %v", warnings)
	}
}

func TestApply_PolicyExcludesAlgo_Dropped(t *testing.T) {
	cfg := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
			{Algo: "ECC", Curves: []string{"P-384"}, MinBits: 384},
		},
	}
	pol := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-384"}, MinBits: 384},
		}},
	}}
	out, warnings := Apply(cfg, pol)
	if len(out.ApprovedAlgorithms) != 1 {
		t.Fatalf("expected 1 entry (RSA dropped), got %d", len(out.ApprovedAlgorithms))
	}
	if out.ApprovedAlgorithms[0].Algo != "ECC" {
		t.Errorf("expected ECC remaining, got %s", out.ApprovedAlgorithms[0].Algo)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "policy excludes RSA") {
		t.Errorf("expected RSA-excluded warning, got: %v", warnings)
	}
}

func TestApply_CurveIntersection(t *testing.T) {
	cfg := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-256", "P-384", "P-521"}, MinBits: 256},
		},
	}
	pol := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-384", "P-521"}, MinBits: 384},
		}},
	}}
	out, _ := Apply(cfg, pol)
	if len(out.ApprovedAlgorithms) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(out.ApprovedAlgorithms))
	}
	got := out.ApprovedAlgorithms[0]
	want := []string{"P-384", "P-521"}
	if len(got.Curves) != len(want) {
		t.Fatalf("expected %d curves (intersection), got %d: %v", len(want), len(got.Curves), got.Curves)
	}
	for i, c := range want {
		if got.Curves[i] != c {
			t.Errorf("curves[%d]: expected %s, got %s", i, c, got.Curves[i])
		}
	}
	if got.MinBits != 384 {
		t.Errorf("expected MinBits=384 (max), got %d", got.MinBits)
	}
}

func TestApply_CurvesIntersectToEmpty_AlgoDropped(t *testing.T) {
	cfg := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-256"}, MinBits: 256},
		},
	}
	pol := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-384", "P-521"}, MinBits: 384},
		}},
	}}
	out, warnings := Apply(cfg, pol)
	if len(out.ApprovedAlgorithms) != 0 {
		t.Errorf("expected ECC dropped (no common curves), got %+v", out.ApprovedAlgorithms)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no common curves for ECC") {
		t.Errorf("expected no-common-curves warning, got: %v", warnings)
	}
}

func TestApply_PolicyHasNoCurves_UserCurvesRetained(t *testing.T) {
	cfg := config.Config{
		ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", Curves: []string{"P-384"}, MinBits: 384},
		},
	}
	pol := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "ECC", MinBits: 384}, // no curves listed → "all curves in family"
		}},
	}}
	out, _ := Apply(cfg, pol)
	if len(out.ApprovedAlgorithms) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(out.ApprovedAlgorithms))
	}
	got := out.ApprovedAlgorithms[0]
	if len(got.Curves) != 1 || got.Curves[0] != "P-384" {
		t.Errorf("expected user curves retained, got: %v", got.Curves)
	}
}

// --- approved_vault_paths tests ---

func TestLoadFromDir_ApprovedVaultPaths_Parses(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00.yaml", `
approved_vault_paths:
  - /var/lib/dotsecenv/vault
  - ~/.local/share/dotsecenv/vault
  - ~/work/*/.dotsecenv/vault
`)
	pol, _, err := loadFromDir(dir, secureStat(0))
	if err != nil {
		t.Fatalf("loadFromDir: %v", err)
	}
	if len(pol.Fragments) != 1 {
		t.Fatalf("expected 1 fragment, got %d", len(pol.Fragments))
	}
	want := []string{
		"/var/lib/dotsecenv/vault",
		"~/.local/share/dotsecenv/vault",
		"~/work/*/.dotsecenv/vault",
	}
	got := pol.Fragments[0].ApprovedVaultPaths
	if len(got) != len(want) {
		t.Fatalf("expected %d patterns, got %d: %v", len(want), len(got), got)
	}
	for i, p := range want {
		if got[i] != p {
			t.Errorf("pattern[%d]: expected %s, got %s", i, p, got[i])
		}
	}
}

func TestLoadFromDir_ApprovedVaultPaths_EmptyRejected(t *testing.T) {
	dir := t.TempDir()
	writeFragment(t, dir, "00.yaml", "approved_vault_paths: []")

	_, _, err := loadFromDir(dir, secureStat(0))
	if err == nil {
		t.Fatal("expected error for empty approved_vault_paths, got nil")
	}
	if !errors.Is(err, ErrEmptyAllowList) {
		t.Errorf("expected ErrEmptyAllowList, got: %v", err)
	}
	if !strings.Contains(err.Error(), "approved_vault_paths") {
		t.Errorf("error should cite the field name, got: %v", err)
	}
}

func TestMergedApprovedVaultPaths_DedupedUnion(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedVaultPaths: []string{
			"/var/lib/dotsecenv/vault",
			"~/.local/share/dotsecenv/vault",
		}},
		{Path: "99.yaml", ApprovedVaultPaths: []string{
			"~/.local/share/dotsecenv/vault", // duplicate
			"~/work/*/.dotsecenv/vault",
		}},
	}}
	patterns, origins := p.MergedApprovedVaultPaths()
	want := []string{
		"/var/lib/dotsecenv/vault",
		"~/.local/share/dotsecenv/vault",
		"~/work/*/.dotsecenv/vault",
	}
	if len(patterns) != len(want) {
		t.Fatalf("expected %d patterns, got %d: %v", len(want), len(patterns), patterns)
	}
	for i, p := range want {
		if patterns[i] != p {
			t.Errorf("pattern[%d]: expected %s, got %s", i, p, patterns[i])
		}
	}
	// Duplicate pattern should list both fragments.
	dup := "~/.local/share/dotsecenv/vault"
	if len(origins[dup]) != 2 {
		t.Errorf("expected 2 origins for duplicated pattern, got: %v", origins[dup])
	}
}

func TestIsVaultPathAllowed_NoPatterns_AllAllowed(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml"}, // no approved_vault_paths
	}}
	if !p.IsVaultPathAllowed("/anything/goes") {
		t.Error("expected unconstrained policy to allow any path")
	}
}

func TestIsVaultPathAllowed_LiteralMatch(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedVaultPaths: []string{
			"/var/lib/dotsecenv/vault",
		}},
	}}
	if !p.IsVaultPathAllowed("/var/lib/dotsecenv/vault") {
		t.Error("expected literal path to match itself")
	}
	if p.IsVaultPathAllowed("/tmp/foo") {
		t.Error("expected unrelated path to be rejected")
	}
}

func TestIsVaultPathAllowed_SingleSegmentGlob(t *testing.T) {
	// Use an absolute test root so we don't depend on the test runner's HOME
	// or the OS-specific resolution that vault.ExpandPath performs (which
	// consults user.Current(), not $HOME).
	root := t.TempDir()

	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedVaultPaths: []string{
			filepath.Join(root, "work/*/.dotsecenv/vault"),
		}},
	}}
	cases := []struct {
		path    string
		allowed bool
	}{
		{filepath.Join(root, "work/projA/.dotsecenv/vault"), true},
		{filepath.Join(root, "work/projB/.dotsecenv/vault"), true},
		// Deep path: filepath.Match `*` does NOT cross / boundaries.
		{filepath.Join(root, "work/team-a/projB/.dotsecenv/vault"), false},
		// Different prefix.
		{filepath.Join(root, "personal/.dotsecenv/vault"), false},
	}
	for _, tc := range cases {
		if got := p.IsVaultPathAllowed(tc.path); got != tc.allowed {
			t.Errorf("IsVaultPathAllowed(%q) = %v, want %v", tc.path, got, tc.allowed)
		}
	}
}

func TestApply_FilterApprovedVaults(t *testing.T) {
	root := t.TempDir()
	allowedVault := filepath.Join(root, "share/dotsecenv/vault")

	cfg := config.Config{
		Vault: []string{
			allowedVault,
			"/tmp/foo",
		},
	}
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedVaultPaths: []string{allowedVault}},
	}}
	out, warnings := Apply(cfg, p)
	if len(out.Vault) != 1 {
		t.Fatalf("expected 1 vault retained, got %d: %v", len(out.Vault), out.Vault)
	}
	if out.Vault[0] != allowedVault {
		t.Errorf("expected %s retained, got %s", allowedVault, out.Vault[0])
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "/tmp/foo") {
		t.Errorf("expected warning citing /tmp/foo, got: %v", warnings)
	}
}

// TestIsVaultPathAllowed_TildeExpansion exercises the ~ -> $HOME expansion
// path against the real current user's home directory (since vault.ExpandPath
// uses user.Current(), not $HOME). Skipped when user.Current() fails (e.g.
// in containers without a passwd entry).
func TestIsVaultPathAllowed_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot resolve home: %v", err)
	}

	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedVaultPaths: []string{
			"~/.local/share/dotsecenv/vault",
		}},
	}}
	target := filepath.Join(home, ".local/share/dotsecenv/vault")
	if !p.IsVaultPathAllowed(target) {
		t.Errorf("expected %s to match ~/.local/share/dotsecenv/vault pattern", target)
	}
}

// --- MergedGPGProgram tests ---

func TestMergedGPGProgram_NoFragmentsSet(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml"}, // GPG omitted entirely
		{Path: "50.yaml", GPG: config.GPGConfig{Program: ""}}, // empty = not set
	}}
	prog, origin, conflicts := p.MergedGPGProgram()
	if prog != "" || origin != "" || len(conflicts) != 0 {
		t.Errorf("expected empty result with no conflicts, got prog=%q origin=%q conflicts=%v", prog, origin, conflicts)
	}
}

func TestMergedGPGProgram_SingleFragment(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}},
	}}
	prog, origin, conflicts := p.MergedGPGProgram()
	if prog != "/usr/bin/gpg" {
		t.Errorf("expected /usr/bin/gpg, got %q", prog)
	}
	if origin != "00.yaml" {
		t.Errorf("expected origin 00.yaml, got %q", origin)
	}
	if len(conflicts) != 0 {
		t.Errorf("expected no conflicts, got: %v", conflicts)
	}
}

func TestMergedGPGProgram_SameValueAcrossFragments_NoConflict(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}},
		{Path: "99.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}}, // same value
	}}
	prog, origin, conflicts := p.MergedGPGProgram()
	if prog != "/usr/bin/gpg" {
		t.Errorf("expected /usr/bin/gpg, got %q", prog)
	}
	if origin != "99.yaml" {
		t.Errorf("expected last-set origin 99.yaml, got %q", origin)
	}
	if len(conflicts) != 0 {
		t.Errorf("same value across fragments should not produce a conflict, got: %v", conflicts)
	}
}

func TestMergedGPGProgram_DifferentValues_LastWinsWithConflict(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00-corp.yaml", GPG: config.GPGConfig{Program: "/opt/homebrew/bin/gpg"}},
		{Path: "99-team.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}},
	}}
	prog, origin, conflicts := p.MergedGPGProgram()
	if prog != "/usr/bin/gpg" {
		t.Errorf("expected last-wins /usr/bin/gpg, got %q", prog)
	}
	if origin != "99-team.yaml" {
		t.Errorf("expected origin 99-team.yaml, got %q", origin)
	}
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict warning, got %d: %v", len(conflicts), conflicts)
	}
	wantSubstrs := []string{
		"policy conflict on gpg.program",
		"overridden to \"/usr/bin/gpg\" by 99-team.yaml",
		"previous value \"/opt/homebrew/bin/gpg\" from 00-corp.yaml",
	}
	for _, s := range wantSubstrs {
		if !strings.Contains(conflicts[0], s) {
			t.Errorf("conflict warning missing %q\ngot: %s", s, conflicts[0])
		}
	}
}

func TestMergedGPGProgram_ChainOfDifferingFragments_NWarnings(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/a"}},
		{Path: "50.yaml", GPG: config.GPGConfig{Program: "/b"}},
		{Path: "99.yaml", GPG: config.GPGConfig{Program: "/c"}},
	}}
	prog, _, conflicts := p.MergedGPGProgram()
	if prog != "/c" {
		t.Errorf("expected last-wins /c, got %q", prog)
	}
	if len(conflicts) != 2 {
		t.Fatalf("expected 2 conflicts (a→b, b→c), got %d: %v", len(conflicts), conflicts)
	}
}

// --- MergedBehavior tests ---

func ptrBool(v bool) *bool { return &v }

func TestMergedBehavior_NoFragmentsSet(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml"},
	}}
	b, origins, conflicts := p.MergedBehavior()
	if b.RequireExplicitVaultUpgrade != nil || b.RestrictToConfiguredVaults != nil {
		t.Errorf("expected zero behavior, got %+v", b)
	}
	if len(origins) != 0 || len(conflicts) != 0 {
		t.Errorf("expected no origins/conflicts, got origins=%v conflicts=%v", origins, conflicts)
	}
}

func TestMergedBehavior_SingleFragment_OneField(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(true),
		}},
	}}
	b, origins, conflicts := p.MergedBehavior()
	if b.RestrictToConfiguredVaults == nil || !*b.RestrictToConfiguredVaults {
		t.Errorf("expected RestrictToConfiguredVaults=true, got %v", b.RestrictToConfiguredVaults)
	}
	if b.RequireExplicitVaultUpgrade != nil {
		t.Errorf("expected RequireExplicitVaultUpgrade=nil, got %v", b.RequireExplicitVaultUpgrade)
	}
	if origins["behavior.restrict_to_configured_vaults"] != "00.yaml" {
		t.Errorf("expected origin 00.yaml, got %v", origins)
	}
	if len(conflicts) != 0 {
		t.Errorf("expected no conflicts, got: %v", conflicts)
	}
}

func TestMergedBehavior_PerFieldIndependence(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", Behavior: config.BehaviorConfig{
			RequireExplicitVaultUpgrade: ptrBool(true),
		}},
		{Path: "99.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(true),
		}},
	}}
	b, origins, conflicts := p.MergedBehavior()
	if b.RequireExplicitVaultUpgrade == nil || !*b.RequireExplicitVaultUpgrade {
		t.Errorf("expected RequireExplicitVaultUpgrade=true, got %v", b.RequireExplicitVaultUpgrade)
	}
	if b.RestrictToConfiguredVaults == nil || !*b.RestrictToConfiguredVaults {
		t.Errorf("expected RestrictToConfiguredVaults=true, got %v", b.RestrictToConfiguredVaults)
	}
	if origins["behavior.require_explicit_vault_upgrade"] != "00.yaml" {
		t.Errorf("expected require_explicit origin 00.yaml, got %v", origins)
	}
	if origins["behavior.restrict_to_configured_vaults"] != "99.yaml" {
		t.Errorf("expected restrict_to origin 99.yaml, got %v", origins)
	}
	if len(conflicts) != 0 {
		t.Errorf("per-field independence should produce no conflicts, got: %v", conflicts)
	}
}

func TestMergedBehavior_SameField_DifferentValues_LastWinsWithConflict(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00-corp.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(false),
		}},
		{Path: "99-team.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(true),
		}},
	}}
	b, origins, conflicts := p.MergedBehavior()
	if b.RestrictToConfiguredVaults == nil || !*b.RestrictToConfiguredVaults {
		t.Errorf("expected last-wins true, got %v", b.RestrictToConfiguredVaults)
	}
	if origins["behavior.restrict_to_configured_vaults"] != "99-team.yaml" {
		t.Errorf("expected origin 99-team.yaml, got %v", origins)
	}
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(conflicts), conflicts)
	}
	if !strings.Contains(conflicts[0], "behavior.restrict_to_configured_vaults") ||
		!strings.Contains(conflicts[0], "99-team.yaml") ||
		!strings.Contains(conflicts[0], "00-corp.yaml") {
		t.Errorf("conflict missing expected substrings: %s", conflicts[0])
	}
}

func TestMergedBehavior_SameField_SameValue_NoConflict(t *testing.T) {
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(true),
		}},
		{Path: "99.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(true),
		}},
	}}
	_, _, conflicts := p.MergedBehavior()
	if len(conflicts) != 0 {
		t.Errorf("same value across fragments should not produce a conflict, got: %v", conflicts)
	}
}

// --- Apply scalar override tests ---

func TestApply_GPGProgram_PolicySetUserUnset_NoWarning(t *testing.T) {
	cfg := config.Config{GPG: config.GPGConfig{Program: ""}}
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}},
	}}
	out, warnings := Apply(cfg, p)
	if out.GPG.Program != "/usr/bin/gpg" {
		t.Errorf("expected policy value /usr/bin/gpg, got %q", out.GPG.Program)
	}
	for _, w := range warnings {
		if strings.Contains(w, "policy overrides user gpg.program") {
			t.Errorf("did not expect override warning when user had no value, got: %s", w)
		}
	}
}

func TestApply_GPGProgram_PolicyOverridesUserDifferentValue_Warning(t *testing.T) {
	cfg := config.Config{GPG: config.GPGConfig{Program: "/opt/homebrew/bin/gpg"}}
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}},
	}}
	out, warnings := Apply(cfg, p)
	if out.GPG.Program != "/usr/bin/gpg" {
		t.Errorf("expected policy value /usr/bin/gpg, got %q", out.GPG.Program)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "policy overrides user gpg.program") &&
			strings.Contains(w, "/opt/homebrew/bin/gpg") &&
			strings.Contains(w, "/usr/bin/gpg") &&
			strings.Contains(w, "00.yaml") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected user-override warning, got: %v", warnings)
	}
}

func TestApply_GPGProgram_PolicySameAsUser_NoWarning(t *testing.T) {
	cfg := config.Config{GPG: config.GPGConfig{Program: "/usr/bin/gpg"}}
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/usr/bin/gpg"}},
	}}
	out, warnings := Apply(cfg, p)
	if out.GPG.Program != "/usr/bin/gpg" {
		t.Errorf("expected unchanged value, got %q", out.GPG.Program)
	}
	for _, w := range warnings {
		if strings.Contains(w, "overrides user") {
			t.Errorf("matched values should not produce override warning, got: %s", w)
		}
	}
}

func TestApply_Behavior_PolicyOverridesUserDifferentValue_Warning(t *testing.T) {
	cfg := config.Config{Behavior: config.BehaviorConfig{
		RestrictToConfiguredVaults: ptrBool(false),
	}}
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", Behavior: config.BehaviorConfig{
			RestrictToConfiguredVaults: ptrBool(true),
		}},
	}}
	out, warnings := Apply(cfg, p)
	if out.Behavior.RestrictToConfiguredVaults == nil || !*out.Behavior.RestrictToConfiguredVaults {
		t.Errorf("expected policy value true, got %v", out.Behavior.RestrictToConfiguredVaults)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "policy overrides user behavior.restrict_to_configured_vaults") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected user-override warning, got: %v", warnings)
	}
}

func TestApply_Behavior_NoPolicyConstraint_UserValueRetained(t *testing.T) {
	cfg := config.Config{Behavior: config.BehaviorConfig{
		RestrictToConfiguredVaults: ptrBool(true),
	}}
	// Policy has approved_algorithms but no behavior fields — just to make
	// the policy non-empty; user behavior should be untouched.
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		}},
	}}
	out, _ := Apply(cfg, p)
	if out.Behavior.RestrictToConfiguredVaults == nil || !*out.Behavior.RestrictToConfiguredVaults {
		t.Errorf("expected user value retained when policy has no behavior constraint, got %v", out.Behavior.RestrictToConfiguredVaults)
	}
}

func TestApply_ConflictWarningsAlsoSurfaceForUser(t *testing.T) {
	// Two fragments disagree on gpg.program. The conflict should surface in
	// Apply's warnings (in addition to the user-override warning).
	cfg := config.Config{GPG: config.GPGConfig{Program: "/x/gpg"}}
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", GPG: config.GPGConfig{Program: "/a/gpg"}},
		{Path: "99.yaml", GPG: config.GPGConfig{Program: "/b/gpg"}},
	}}
	out, warnings := Apply(cfg, p)
	if out.GPG.Program != "/b/gpg" {
		t.Errorf("expected last-wins /b/gpg, got %q", out.GPG.Program)
	}
	var (
		sawConflict bool
		sawOverride bool
	)
	for _, w := range warnings {
		if strings.Contains(w, "policy conflict on gpg.program") {
			sawConflict = true
		}
		if strings.Contains(w, "policy overrides user gpg.program") {
			sawOverride = true
		}
	}
	if !sawConflict {
		t.Errorf("expected cross-fragment conflict warning, got: %v", warnings)
	}
	if !sawOverride {
		t.Errorf("expected user-override warning, got: %v", warnings)
	}
}

func TestApply_NoVaultPolicy_VaultsUnchanged(t *testing.T) {
	cfg := config.Config{
		Vault: []string{"/tmp/foo", "/tmp/bar"},
	}
	// Policy has approved_algorithms but no approved_vault_paths.
	p := Policy{Fragments: []Fragment{
		{Path: "00.yaml", ApprovedAlgorithms: []config.ApprovedAlgorithm{
			{Algo: "RSA", MinBits: 2048},
		}},
	}}
	out, _ := Apply(cfg, p)
	if len(out.Vault) != 2 {
		t.Errorf("expected vaults unchanged when policy has no vault constraint, got %v", out.Vault)
	}
}
