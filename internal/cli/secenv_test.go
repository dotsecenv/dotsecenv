package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

func TestBuildRefsFromInfos(t *testing.T) {
	infos := []vault.SecretKeyInfo{
		{Key: "FOO"},
		{Key: "prod::DB_PASSWORD"},
		{Key: "GONE", Deleted: true}, // dropped
		{Key: "1badkey"},             // unparseable -> warned + dropped
	}
	var stdout, stderr bytes.Buffer
	h := output.NewHandler(&stdout, &stderr)

	refs := buildRefsFromInfos(infos, h)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d: %+v", len(refs), refs)
	}
	got := map[string]string{}
	for _, r := range refs {
		got[r.EnvName] = r.Line()
	}
	if got["FOO"] != "FOO={dotsecenv/}" {
		t.Errorf("FOO line = %q", got["FOO"])
	}
	if got["PROD_DB_PASSWORD"] != "PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}" {
		t.Errorf("namespaced line = %q", got["PROD_DB_PASSWORD"])
	}
	if !strings.Contains(stderr.String(), "skipping secret") {
		t.Errorf("expected warning for unparseable key, stderr = %q", stderr.String())
	}
}

func newBatchCLI(mock *MockVaultResolver, stdout, stderr *bytes.Buffer, silent bool) *CLI {
	return &CLI{
		vaultResolver: mock,
		output:        output.NewHandler(stdout, stderr, output.WithSilent(silent)),
	}
}

func mockWithSecrets(keys ...string) *MockVaultResolver {
	mock := NewMockVaultResolver()
	mock.VaultPaths = []string{"/tmp/v1"}
	mock.VaultEntries = []vault.VaultEntry{{Path: "/tmp/v1"}}
	mock.Secrets[0] = make(map[string]vault.Secret)
	for _, k := range keys {
		mock.Secrets[0][k] = vault.Secret{Key: k}
	}
	return mock
}

func TestInitSecenvBatchCreates0600(t *testing.T) {
	dir := t.TempDir()
	mock := mockWithSecrets("FOO", "prod::DB_PASSWORD")
	// A deleted secret must not be written.
	mock.Secrets[0]["GONE"] = vault.Secret{Key: "GONE", Values: []vault.SecretValue{{Deleted: true}}}

	var stdout, stderr bytes.Buffer
	cli := newBatchCLI(mock, &stdout, &stderr, false)
	if err := cli.InitSecenv(dir, true); err != nil {
		t.Fatalf("InitSecenv: %v", err)
	}

	path := filepath.Join(dir, ".secenv")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}

	content := string(mustRead(t, path))
	if !strings.Contains(content, "FOO={dotsecenv/}") {
		t.Errorf("missing FOO line:\n%s", content)
	}
	if !strings.Contains(content, "PROD_DB_PASSWORD={dotsecenv/prod::DB_PASSWORD}") {
		t.Errorf("missing namespaced line:\n%s", content)
	}
	if strings.Contains(content, "GONE") {
		t.Errorf("deleted secret must not be written:\n%s", content)
	}
}

func TestInitSecenvBatchIdempotentWithWarnings(t *testing.T) {
	dir := t.TempDir()
	mock := mockWithSecrets("FOO", "BAR")

	var o1, e1 bytes.Buffer
	if err := newBatchCLI(mock, &o1, &e1, false).InitSecenv(dir, true); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := mustRead(t, filepath.Join(dir, ".secenv"))

	var o2, e2 bytes.Buffer
	if err := newBatchCLI(mock, &o2, &e2, false).InitSecenv(dir, true); err != nil {
		t.Fatalf("second run: %v", err)
	}
	after := mustRead(t, filepath.Join(dir, ".secenv"))

	if string(before) != string(after) {
		t.Errorf("file changed on idempotent re-run:\nbefore=%q\nafter=%q", before, after)
	}
	if !strings.Contains(e2.String(), "already present") {
		t.Errorf("expected duplicate warnings on re-run, stderr = %q", e2.String())
	}
}

func TestInitSecenvSilentMutesWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".secenv"), []byte("FOO={dotsecenv/}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mock := mockWithSecrets("FOO")

	var stdout, stderr bytes.Buffer
	if err := newBatchCLI(mock, &stdout, &stderr, true).InitSecenv(dir, true); err != nil {
		t.Fatalf("InitSecenv: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("silent mode should mute warnings, stderr = %q", stderr.String())
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
