// Package policy implements the trusted system policy directory at
// /etc/dotsecenv/policy.d/. Admins drop YAML fragments into the directory
// to constrain every user of the binary; user configs keep full local
// autonomy for fields that policy doesn't touch.
//
// Phase 1 supports one allow-list field: approved_algorithms. The effective
// policy is the union of all fragments (most-permissive merge: same-algo
// entries collapse, curves union, min_bits takes the minimum). The user's
// effective config is then the intersection of the user's approved_algorithms
// with the policy's union.
//
// When the policy directory does not exist, no policy is enforced and the
// binary behaves as before. When the directory exists but contains malformed
// fragments, forbidden keys, empty allow-lists, or insecure permissions, the
// load fails hard with an explicit error citing the offending fragment.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"gopkg.in/yaml.v3"
)

// DefaultDir is the production policy directory. Exposed as a var (not const)
// so tests can override it; production code MUST NOT reassign this value.
var DefaultDir = "/etc/dotsecenv/policy.d"

// Sentinel errors returned by Load. Callers (e.g. dotsecenv policy validate)
// use errors.Is to map these to distinct exit codes. Any of these errors
// from Load() is fatal: dotsecenv refuses to start until the offending
// fragment is fixed or removed. Failing closed is the only safe behavior
// when admin policy can't be parsed.
var (
	// ErrInsecurePermissions indicates a fragment file or the directory has
	// group/other write bits set, or is owned by a non-root user.
	ErrInsecurePermissions = errors.New("insecure policy permissions")

	// ErrForbiddenKey indicates a fragment contains a top-level key that is
	// not allowed in policy fragments (e.g. login, vault).
	ErrForbiddenKey = errors.New("forbidden policy key")

	// ErrEmptyAllowList indicates a fragment sets an allow-list field to an
	// empty list, which is almost certainly an authoring bug. Omit the field
	// entirely instead.
	ErrEmptyAllowList = errors.New("empty allow-list field")

	// ErrMalformedFragment indicates a fragment file could not be parsed as
	// YAML.
	ErrMalformedFragment = errors.New("malformed policy fragment")

	// ErrUnreadableFragment indicates a fragment file could not be read
	// (e.g. permission denied at open time, even though the directory
	// listing exposed the file). Fail closed: a partially-readable policy
	// directory is indistinguishable from tampering, so refuse to start.
	ErrUnreadableFragment = errors.New("unreadable policy fragment")
)

// Policy is the loaded set of policy fragments. Fragments are stored raw so
// per-field origin attribution is computable for `dotsecenv policy list`.
type Policy struct {
	Dir       string     // source directory; empty when no policy enforced
	Fragments []Fragment // fragments in lexical filename order
}

// Empty reports whether no policy is in effect.
func (p Policy) Empty() bool { return len(p.Fragments) == 0 }

// Fragment is one parsed *.yaml file from the policy directory.
type Fragment struct {
	Path               string                     `yaml:"-"` // populated by loader
	ApprovedAlgorithms []config.ApprovedAlgorithm `yaml:"approved_algorithms,omitempty"`
	ApprovedVaultPaths []string                   `yaml:"approved_vault_paths,omitempty"`
	// PR #3 will add: Behavior config.BehaviorConfig and GPG config.GPGConfig
}

// forbiddenKeysPhase1 are top-level YAML keys rejected at fragment load.
// PR #3 will lift "behavior" and "gpg" from this list.
var forbiddenKeysPhase1 = []string{"login", "vault", "behavior", "gpg"}

// Load enumerates *.yaml in DefaultDir (lexical order), validates each
// fragment, and returns the assembled Policy plus per-fragment warnings.
// Returns (Policy{}, nil, nil) when DefaultDir does not exist (no policy
// enforced — distinct from "directory exists but has malformed fragment",
// which is a hard error).
func Load() (Policy, []string, error) {
	return loadFromDir(DefaultDir, os.Stat)
}

// loadFromDir is the testable core of Load. Tests pass a temp directory and
// an injected stat function (production cannot chown root for fixtures).
func loadFromDir(dir string, statFn func(string) (os.FileInfo, error)) (Policy, []string, error) {
	if _, err := statFn(dir); err != nil {
		if os.IsNotExist(err) {
			return Policy{}, nil, nil
		}
		return Policy{}, nil, fmt.Errorf("stat policy dir %s: %w", dir, err)
	}

	if err := checkSecure(dir, statFn); err != nil {
		return Policy{}, nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return Policy{}, nil, fmt.Errorf("read policy dir %s: %w", dir, err)
	}

	var paths []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	sort.Strings(paths)

	var (
		warnings  []string
		fragments []Fragment
	)

	for _, p := range paths {
		if err := checkSecure(p, statFn); err != nil {
			return Policy{}, nil, err
		}

		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return Policy{}, nil, fmt.Errorf("%w: %s: %v", ErrUnreadableFragment, p, readErr)
		}

		if err := rejectForbiddenKeys(p, data); err != nil {
			return Policy{}, nil, err
		}

		var f Fragment
		if err := yaml.Unmarshal(data, &f); err != nil {
			return Policy{}, nil, fmt.Errorf("%w: %s: %v", ErrMalformedFragment, p, err)
		}
		f.Path = p

		if err := rejectEmptyAllowLists(p, f); err != nil {
			return Policy{}, nil, err
		}

		fragments = append(fragments, f)
	}

	return Policy{Dir: dir, Fragments: fragments}, warnings, nil
}

// rejectForbiddenKeys parses the raw YAML and returns ErrForbiddenKey if any
// top-level key in forbiddenKeysPhase1 is present. Mirrors the raw-YAML
// second-pass scan from config.detectLegacyFields.
func rejectForbiddenKeys(path string, data []byte) error {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil // primary parse will surface this as ErrMalformedFragment
	}
	for _, key := range forbiddenKeysPhase1 {
		if _, ok := raw[key]; ok {
			return fmt.Errorf("%w: %s contains '%s:' (not allowed in policy fragments)", ErrForbiddenKey, path, key)
		}
	}
	return nil
}

// rejectEmptyAllowLists guards against `approved_algorithms: []` and
// `approved_vault_paths: []` (the empty-list authoring bug). Omit the
// field or set actual entries.
func rejectEmptyAllowLists(path string, f Fragment) error {
	if f.ApprovedAlgorithms != nil && len(f.ApprovedAlgorithms) == 0 {
		return fmt.Errorf("%w: %s sets approved_algorithms: [] (omit the field instead of setting an empty list)", ErrEmptyAllowList, path)
	}
	if f.ApprovedVaultPaths != nil && len(f.ApprovedVaultPaths) == 0 {
		return fmt.Errorf("%w: %s sets approved_vault_paths: [] (omit the field instead of setting an empty list)", ErrEmptyAllowList, path)
	}
	return nil
}
