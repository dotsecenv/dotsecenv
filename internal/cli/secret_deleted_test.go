package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

const deletedTestFP = "ALICEFP"

// deletedTestCLI builds a CLI over one mock vault per history. The mock GPG
// agent "decrypts" a value to its base64-decoded ciphertext and records every
// ciphertext it was handed.
func deletedTestCLI(t *testing.T, histories ...[]vault.SecretValue) (*CLI, *bytes.Buffer, *bytes.Buffer, *[]string) {
	t.Helper()
	t.Setenv("DOTSECENV_CONFIG", "")

	resolver := NewMockVaultResolver()
	for i, values := range histories {
		path := fmt.Sprintf("/vault%d", i+1)
		resolver.VaultPaths = append(resolver.VaultPaths, path)
		resolver.VaultEntries = append(resolver.VaultEntries, vault.VaultEntry{Path: path})
		if values != nil {
			resolver.Secrets[i] = map[string]vault.Secret{"SEC": {Key: "SEC", Values: values}}
		}
	}

	var decrypted []string
	gpgClient := &MockGPGClientWithDecrypt{
		MockGPGClient: NewMockGPGClient(),
		DecryptFunc: func(ciphertext []byte, fingerprint string) ([]byte, error) {
			decrypted = append(decrypted, string(ciphertext))
			if len(ciphertext) == 0 {
				return nil, fmt.Errorf("no ciphertext")
			}
			return ciphertext, nil
		},
	}

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cli := &CLI{
		config: config.Config{
			ApprovedAlgorithms: []config.ApprovedAlgorithm{{Algo: "RSA", MinBits: 2048}},
			Login:              newTestSignedLogin(t, deletedTestFP),
		},
		vaultResolver: resolver,
		gpgClient:     gpgClient,
		stdin:         strings.NewReader(""),
		output:        output.NewHandler(stdout, stderr),
		hasTTY:        func() bool { return true },
	}
	return cli, stdout, stderr, &decrypted
}

// storedValue is a value encrypted (base64-encoded, for the mock) to fingerprints.
func storedValue(at time.Time, plaintext string, fps ...string) vault.SecretValue {
	return vault.SecretValue{AddedAt: at, Value: base64.StdEncoding.EncodeToString([]byte(plaintext)), AvailableTo: fps}
}

func deletionAt(at time.Time) vault.SecretValue {
	return vault.SecretValue{AddedAt: at, AvailableTo: []string{}, Deleted: true}
}

func TestSecretGetAll_MarksDeletedValues(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cli, stdout, stderr, decrypted := deletedTestCLI(t, []vault.SecretValue{
		storedValue(now.Add(-2*time.Hour), "old", deletedTestFP),
		deletionAt(now.Add(-time.Hour)),
		storedValue(now, "new", deletedTestFP),
	})

	if err := cli.SecretGet("SEC", true, false, false, "", 0); err != nil {
		t.Fatalf("SecretGet --all: %s", err.Message)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %q", stdout.String())
	}
	if !strings.HasSuffix(lines[0], "(/vault1): new") {
		t.Errorf("newest line = %q, want the live value unmarked", lines[0])
	}
	if !strings.HasSuffix(lines[1], "(/vault1) [deleted]: old") {
		t.Errorf("older line = %q, want the deleted value marked", lines[1])
	}
	for _, c := range *decrypted {
		if c == "" {
			t.Error("the deletion marker was handed to GPG")
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr: %s", stderr.String())
	}
}

// A secret whose latest entry is a deletion marker still lists its history
// under --all, every value flagged deleted, in single-vault mode too.
func TestSecretGetAll_DeletedSecretListsHistory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cli, stdout, _, _ := deletedTestCLI(t, []vault.SecretValue{
		storedValue(now.Add(-time.Hour), "old", deletedTestFP),
		deletionAt(now),
	})

	if err := cli.SecretGet("SEC", true, false, true, "", 1); err != nil {
		t.Fatalf("SecretGet --all --json -v 1: %s", err.Message)
	}

	var results []SecretValueJSON
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, stdout.String())
	}
	if len(results) != 1 || results[0].Value != "old" || !results[0].Deleted {
		t.Errorf("results = %+v, want one deleted value 'old'", results)
	}
}

func TestSecretGet_DeletedSecretErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	history := []vault.SecretValue{storedValue(now.Add(-time.Hour), "old", deletedTestFP), deletionAt(now)}

	for _, fromIndex := range []int{0, 1} {
		cli, stdout, _, _ := deletedTestCLI(t, history)
		err := cli.SecretGet("SEC", false, false, false, "", fromIndex)
		if err == nil || !strings.Contains(err.Message, "has been deleted") {
			t.Errorf("-v %d: got %v, want 'has been deleted'", fromIndex, err)
		}
		if stdout.Len() != 0 {
			t.Errorf("-v %d: printed %q for a deleted secret", fromIndex, stdout.String())
		}
	}
}

// A deletion in the first vault does not hide the second vault's value, and
// the JSON names the vault the value came from.
func TestSecretGet_DeletedVaultFallsThrough(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cli, stdout, _, _ := deletedTestCLI(t,
		[]vault.SecretValue{storedValue(now.Add(-time.Hour), "gone", deletedTestFP), deletionAt(now)},
		[]vault.SecretValue{storedValue(now.Add(-time.Hour), "kept", deletedTestFP)},
	)

	if err := cli.SecretGet("SEC", false, false, true, "", 0); err != nil {
		t.Fatalf("SecretGet --json: %s", err.Message)
	}
	var got SecretValueJSON
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, stdout.String())
	}
	if got.Value != "kept" || got.Vault != "/vault2" {
		t.Errorf("got %+v, want 'kept' from /vault2", got)
	}
}

// --last only considers values after the most recent deletion.
func TestSecretGetLast_SkipsDeletedValues(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cli, _, _, _ := deletedTestCLI(t, []vault.SecretValue{
		storedValue(now.Add(-2*time.Hour), "old", deletedTestFP),
		deletionAt(now.Add(-time.Hour)),
		storedValue(now, "new", "BOBFP"),
	})

	err := cli.SecretGet("SEC", false, true, false, "", 0)
	if err == nil || !strings.Contains(err.Message, "access denied") {
		t.Errorf("got %v, want access denied rather than the deleted value", err)
	}
}

func TestSecretShareRevoke_DeletedSecret(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	history := []vault.SecretValue{storedValue(now.Add(-time.Hour), "old", deletedTestFP, "BOBFP"), deletionAt(now)}

	cli, _, _, _ := deletedTestCLI(t, history)
	if err := cli.SecretShare("SEC", "CAROLFP", -1); err == nil || !strings.Contains(err.Message, "has been deleted") {
		t.Errorf("share: got %v, want 'has been deleted'", err)
	}
	if err := cli.SecretRevoke("SEC", "BOBFP", -1); err == nil || !strings.Contains(err.Message, "has been deleted") {
		t.Errorf("revoke: got %v, want 'has been deleted'", err)
	}
}
