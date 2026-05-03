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
	cases := []struct {
		key  string
		body string
	}{
		{"login", "login:\n  fingerprint: ABCD\n"},
		{"vault", "vault:\n  - /tmp/v\n"},
		{"behavior", "behavior:\n  restrict_to_configured_vaults: true\n"},
		{"gpg", "gpg:\n  program: /usr/bin/gpg\n"},
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
