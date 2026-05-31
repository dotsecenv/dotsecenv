// Package secenv reads and writes the reference lines in a project's .secenv
// file. It derives the env-var name and {dotsecenv/...} placeholder for a vault
// secret key and appends new references without touching what is already there.
//
// This is the only writer of .secenv in the CLI; the shell plugin remains the
// reader. The reference syntax matches examples/05-secenv-shell-plugin/.secenv.
package secenv

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

// Ref is a single .secenv reference line: an env-var name bound to a vault
// secret key. SecretKey holds the canonical vault key (e.g. "prod::DB_PASSWORD"
// or "FOO"); Line renders the short same-name form when it equals EnvName.
type Ref struct {
	EnvName   string
	SecretKey string
}

// Line renders the .secenv line for this reference.
//
//	FOO={dotsecenv/}                          when EnvName == SecretKey
//	PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}   otherwise
func (r Ref) Line() string {
	if r.SecretKey == "" || r.SecretKey == r.EnvName {
		return r.EnvName + "={dotsecenv/}"
	}
	return r.EnvName + "={dotsecenv/" + r.SecretKey + "}"
}

// DeriveRef turns a canonical vault secret key into a Ref.
//
// A non-namespaced key keeps its name: "FOO" -> FOO={dotsecenv/}. A namespaced
// key is prefixed: "prod::DB_PASSWORD" -> PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}.
// Dots are legal in vault key names but not in shell env-var names, so they
// become underscores; the placeholder then carries the explicit key so the
// secret still resolves (APP.DOMAIN.ORG -> APP_DOMAIN_ORG={dotsecenv/APP.DOMAIN.ORG}).
func DeriveRef(secretKey string) (Ref, error) {
	sk, err := vault.ParseSecretKey(secretKey)
	if err != nil {
		return Ref{}, err
	}

	nameEnv := strings.ReplaceAll(sk.Name, ".", "_")
	envName := nameEnv
	if sk.Namespace != nil {
		envName = strings.ToUpper(*sk.Namespace) + "_" + nameEnv
	}

	return Ref{EnvName: envName, SecretKey: sk.String()}, nil
}

// ReadEnvNames returns the set of env-var names (the text left of the first '=')
// already defined in the .secenv file at path. Blank lines and '#' comments are
// ignored, as are lines without an '='. A missing file yields an empty set and
// no error. Names are compared case-sensitively, matching shell env semantics.
func ReadEnvNames(path string) (map[string]bool, error) {
	set := make(map[string]bool)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return set, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		if name != "" {
			set[name] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return set, nil
}

// Append writes refs to the .secenv file at path, creating it mode 0600 when
// missing and preserving the mode of an existing file. Any ref whose EnvName is
// already in existing is skipped rather than overwritten; .secenv is append-only
// here. Refs are also deduplicated against each other within this call (first
// wins), so two keys that derive the same env-var name collapse to one line.
// When nothing is left to write, the file is not touched.
//
// existing may be the set returned by ReadEnvNames; Append mutates it, adding
// each written EnvName so later refs in the same call dedup against it.
func Append(path string, refs []Ref, existing map[string]bool) (written, skipped []Ref, err error) {
	if existing == nil {
		existing = make(map[string]bool)
	}

	for _, r := range refs {
		if existing[r.EnvName] {
			skipped = append(skipped, r)
			continue
		}
		existing[r.EnvName] = true
		written = append(written, r)
	}
	if len(written) == 0 {
		return written, skipped, nil
	}

	info, statErr := os.Stat(path)
	fileExists := statErr == nil
	if statErr != nil && !os.IsNotExist(statErr) {
		return written, skipped, statErr
	}

	var buf bytes.Buffer
	// Keep a newline boundary so the first appended line never joins a file
	// whose last line lacks a trailing newline.
	if fileExists && info.Size() > 0 {
		lacksNL, nlErr := lacksTrailingNewline(path)
		if nlErr != nil {
			return written, skipped, nlErr
		}
		if lacksNL {
			buf.WriteByte('\n')
		}
	}
	for _, r := range written {
		buf.WriteString(r.Line())
		buf.WriteByte('\n')
	}

	flag := os.O_WRONLY | os.O_APPEND
	if !fileExists {
		flag |= os.O_CREATE
	}
	f, openErr := os.OpenFile(path, flag, 0o600)
	if openErr != nil {
		return written, skipped, openErr
	}
	if _, wErr := f.Write(buf.Bytes()); wErr != nil {
		_ = f.Close()
		return written, skipped, wErr
	}
	if cErr := f.Close(); cErr != nil {
		return written, skipped, cErr
	}

	// Guarantee 0600 on a file we created, regardless of the process umask.
	if !fileExists {
		if chErr := os.Chmod(path, 0o600); chErr != nil {
			return written, skipped, chErr
		}
	}
	return written, skipped, nil
}

// lacksTrailingNewline reports whether the file's last byte is not a newline.
func lacksTrailingNewline(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if len(data) == 0 {
		return false, nil
	}
	return data[len(data)-1] != '\n', nil
}
