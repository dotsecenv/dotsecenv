package cli

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/gpg"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

func TestSecretGet_PinentryRequired(t *testing.T) {
	for _, granted := range []bool{false, true} {
		for _, mode := range []struct {
			name  string
			all   bool
			last  bool
			path  string
			index int
		}{
			{name: "default"},
			{name: "all", all: true},
			{name: "index", index: 1},
			{name: "index all", index: 1, all: true},
			{name: "path", path: "/vault"},
			{name: "path all", path: "/vault", all: true},
			{name: "last", last: true},
		} {
			if mode.last && !granted {
				continue
			}
			t.Run(fmt.Sprintf("%s/granted=%t", mode.name, granted), func(t *testing.T) {
				t.Setenv("DOTSECENV_CONFIG", "")
				fp := "LOGGED_IN_FP"
				recipient := "OTHER_FP"
				if granted {
					recipient = fp
				}
				resolver := NewMockVaultResolver()
				resolver.VaultPaths = []string{"/vault"}
				resolver.VaultEntries = []vault.VaultEntry{{Path: "/vault"}}
				resolver.Managers = map[int]*vault.Manager{0: vault.NewManager("/vault", false)}
				resolver.Secrets[0] = map[string]vault.Secret{
					"HCLOUD_TOKEN": {
						Key: "HCLOUD_TOKEN",
						Values: []vault.SecretValue{
							{AddedAt: time.Now().Add(-time.Hour), Value: "b2xk", AvailableTo: []string{recipient}},
							{AddedAt: time.Now(), Value: "bmV3", AvailableTo: []string{recipient}},
						},
					},
				}
				calls := 0
				client := &MockGPGClientWithDecrypt{
					MockGPGClient: NewMockGPGClient(),
					DecryptFunc: func([]byte, string) ([]byte, error) {
						calls++
						return nil, fmt.Errorf("agent failure: %w", gpg.ErrPinentryRequired)
					},
				}
				var stdout, stderr bytes.Buffer
				cli := &CLI{
					config:        config.Config{Login: newTestSignedLogin(t, fp)},
					vaultResolver: resolver,
					gpgClient:     client,
					output:        output.NewHandler(&stdout, &stderr),
					hasTTY:        func() bool { return true },
				}
				err := cli.SecretGet("HCLOUD_TOKEN", mode.all, mode.last, false, mode.path, mode.index)
				if err == nil || err.ExitCode != ExitGPGError || !strings.Contains(err.Message, "GPG_PINENTRY_REQUIRED") {
					t.Fatalf("got %v, want pinentry required with exit code 4", err)
				}
				if calls != 1 || stdout.Len() != 0 || stderr.Len() != 0 {
					t.Errorf("calls = %d, stdout = %q, stderr = %q; want one attempt with no output", calls, stdout.String(), stderr.String())
				}
			})
		}
	}
}

type pinentrySigningClient struct {
	*MockGPGClientWithDecrypt
	failAt int
	calls  int
}

func (c *pinentrySigningClient) SignDataWithAgent(string, []byte) (string, error) {
	c.calls++
	if c.calls == c.failAt {
		return "", fmt.Errorf("signing: %w", gpg.ErrPinentryRequired)
	}
	return "signature", nil
}

func TestSecretMutations_PinentryRequired(t *testing.T) {
	cases := []struct {
		name        string
		signAt      int
		decryptFail bool
		skipFirst   bool
		run         func(*CLI) *Error
	}{
		{"store definition", 1, false, false, func(c *CLI) *Error { return c.SecretPut("HCLOUD_TOKEN", "", 1, "synthetic", StoreShareAlways) }},
		{"store value", 2, false, false, func(c *CLI) *Error { return c.SecretPut("HCLOUD_TOKEN", "", 1, "synthetic", StoreShareAlways) }},
		{"forget", 1, false, false, func(c *CLI) *Error { return c.SecretForget("HCLOUD_TOKEN", "", 1, false) }},
		{"share sign", 1, false, false, func(c *CLI) *Error { return c.SecretShare("HCLOUD_TOKEN", "TARGET", 0) }},
		{"revoke sign", 1, false, false, func(c *CLI) *Error { return c.SecretRevoke("HCLOUD_TOKEN", "OTHER", 0) }},
		{"share all sign", 1, false, false, func(c *CLI) *Error { return c.SecretShareAll("HCLOUD_TOKEN", "TARGET") }},
		{"share all skipped", 1, false, true, func(c *CLI) *Error { return c.SecretShareAll("HCLOUD_TOKEN", "TARGET") }},
		{"revoke all sign", 1, false, false, func(c *CLI) *Error { return c.SecretRevokeAll("HCLOUD_TOKEN", "OTHER") }},
		{"revoke all skipped", 1, false, true, func(c *CLI) *Error { return c.SecretRevokeAll("HCLOUD_TOKEN", "OTHER") }},
		{"share all decrypt", 0, true, false, func(c *CLI) *Error { return c.SecretShareAll("HCLOUD_TOKEN", "TARGET") }},
		{"revoke all decrypt", 0, true, false, func(c *CLI) *Error { return c.SecretRevokeAll("HCLOUD_TOKEN", "OTHER") }},
		{"identity all sign", 1, false, false, func(c *CLI) *Error { return c.IdentityAdd("NEW", true, "", 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOTSECENV_CONFIG", "")
			paths := []string{"/vault0", "/vault1", "/vault2"}
			cli, resolver, _ := newSecretStoreCLI(t, paths, paths)
			resolver.Managers = make(map[int]*vault.Manager)
			for i := range paths {
				if tc.skipFirst && i == 0 {
					continue
				}
				manager := vault.NewManager(filepath.Join(t.TempDir(), "vault"), false)
				if err := manager.OpenAndLock(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = manager.Unlock() })
				now := time.Now().UTC()
				secret := vault.Secret{
					Key: "HCLOUD_TOKEN", AddedAt: now,
					Values: []vault.SecretValue{{AddedAt: now, Value: "c3ludGhldGlj", AvailableTo: []string{"MYFINGERPRINT", "OTHER"}}},
				}
				manager.AddSecret(secret)
				if manager.GetSecretByKey("HCLOUD_TOKEN") == nil {
					t.Fatal("fixture secret was not added")
				}
				resolver.Managers[i] = manager
				resolver.Secrets[i] = map[string]vault.Secret{"HCLOUD_TOKEN": secret}
				resolver.IdentitiesByVault[i] = make(map[string]vault.Identity)
				for _, fp := range []string{"MYFINGERPRINT", "OTHER", "TARGET"} {
					identity := vault.Identity{Fingerprint: fp, PublicKey: "synthetic", AlgorithmBits: 2048}
					resolver.Identities[fp] = identity
					resolver.IdentitiesByVault[i][fp] = identity
				}
			}
			decryptCalls := 0
			client := &pinentrySigningClient{
				MockGPGClientWithDecrypt: &MockGPGClientWithDecrypt{
					MockGPGClient: NewMockGPGClient(),
					DecryptFunc: func([]byte, string) ([]byte, error) {
						decryptCalls++
						if tc.decryptFail {
							return nil, gpg.ErrPinentryRequired
						}
						return []byte("synthetic"), nil
					},
				},
				failAt: tc.signAt,
			}
			cli.gpgClient = client
			client.PublicKeyInfo["NEW"] = gpg.KeyInfo{Fingerprint: "NEW", Algorithm: "RSA", AlgorithmBits: 2048, CanEncrypt: true, PublicKeyBase64: "synthetic"}
			err := tc.run(cli)
			if err == nil || err.ExitCode != ExitGPGError || !strings.Contains(err.Message, "GPG_PINENTRY_REQUIRED") {
				t.Fatalf("got %v, want pinentry-required error with exit code 4", err)
			}
			if client.calls != tc.signAt || decryptCalls > 1 || len(resolver.SavedVaults) != 0 {
				t.Errorf("sign calls = %d, decrypt calls = %d, saved vaults = %v", client.calls, decryptCalls, resolver.SavedVaults)
			}
		})
	}
}
