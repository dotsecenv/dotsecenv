package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/config"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/vault"
)

func TestSecretGet_StructuredWarnings(t *testing.T) {
	for _, index := range []int{0, 1} {
		for _, hasTTY := range []bool{false, true} {
			for _, mode := range []struct {
				name   string
				json   bool
				silent bool
			}{
				{name: "text"},
				{name: "silent", silent: true},
				{name: "json", json: true},
				{name: "silent json", json: true, silent: true},
			} {
				t.Run(fmt.Sprintf("index=%d/tty=%t/%s", index, hasTTY, mode.name), func(t *testing.T) {
					const fp = "TESTFINGERPRINT"
					addedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
					resolver := NewMockVaultResolver()
					resolver.VaultPaths = []string{"/vault"}
					resolver.VaultEntries = []vault.VaultEntry{{Path: "/vault"}}
					resolver.Secrets[0] = map[string]vault.Secret{
						"MY_SECRET": {
							Key: "MY_SECRET",
							Values: []vault.SecretValue{
								{AddedAt: addedAt, Value: "Z29vZA==", AvailableTo: []string{fp}},
								{AddedAt: addedAt.Add(time.Hour), Value: "YmFk", AvailableTo: []string{fp}},
								{AddedAt: addedAt.Add(2 * time.Hour), Value: "!invalid base64!", AvailableTo: []string{fp}},
							},
						},
					}
					client := &MockGPGClientWithDecrypt{
						MockGPGClient: NewMockGPGClient(),
						DecryptFunc: func(ciphertext []byte, _ string) ([]byte, error) {
							if string(ciphertext) == "bad" {
								return nil, fmt.Errorf("decryption failed")
							}
							return []byte("decrypted_value"), nil
						},
					}
					var stdout, stderr bytes.Buffer
					cli := &CLI{
						config:        config.Config{Login: newTestSignedLogin(t, fp)},
						vaultResolver: resolver,
						gpgClient:     client,
						Silent:        mode.silent,
						output:        output.NewHandler(&stdout, &stderr, output.WithSilent(mode.silent), output.WithJSON(mode.json)),
						hasTTY:        func() bool { return hasTTY },
					}
					if err := cli.SecretGet("MY_SECRET", true, false, mode.json, "", index); err != nil {
						t.Fatalf("SecretGet: %v", err)
					}
					if !strings.Contains(stdout.String(), "decrypted_value") {
						t.Fatalf("readable version missing from stdout: %q", stdout.String())
					}

					wantCodes := []output.Code{output.CodeWarnDecodeFailure, output.CodeWarnDecryptFailure}
					wantMessages := []string{"failed to decode value from", "failed to decrypt value from"}
					if !hasTTY {
						wantCodes = append([]output.Code{output.CodeWarnGeneric}, wantCodes...)
						wantMessages = append([]string{"decrypting in non-interactive terminal"}, wantMessages...)
					}
					warnings := cli.Output().GetWarnings()
					if len(warnings) != len(wantCodes) {
						t.Fatalf("got %d warnings, want %d: %q", len(warnings), len(wantCodes), stderr.String())
					}
					var wantStderr strings.Builder
					for i, warning := range warnings {
						if warning.Code != wantCodes[i] || !warning.Code.IsWarning() || !strings.Contains(warning.Message, wantMessages[i]) {
							t.Errorf("warning %d = %+v, want %s with %q", i, warning, wantCodes[i], wantMessages[i])
						}
						fmt.Fprintf(&wantStderr, "warning: %s\n", warning.Message)
					}
					if mode.silent || mode.json {
						if stderr.Len() != 0 {
							t.Errorf("unexpected stderr: %q", stderr.String())
						}
					} else if stderr.String() != wantStderr.String() {
						t.Errorf("stderr = %q, want %q", stderr.String(), wantStderr.String())
					}
					if mode.json {
						stdout.Reset()
						if err := cli.Output().WriteJSON(nil, nil); err != nil {
							t.Fatal(err)
						}
						var envelope struct {
							Warnings []*output.Warning `json:"warnings"`
						}
						if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
							t.Fatal(err)
						}
						if len(envelope.Warnings) != len(wantCodes) {
							t.Fatalf("JSON warnings = %v, want %v", envelope.Warnings, wantCodes)
						}
						for i, warning := range envelope.Warnings {
							if warning.Code != wantCodes[i] {
								t.Errorf("JSON warning %d code = %s, want %s", i, warning.Code, wantCodes[i])
							}
						}
					}
				})
			}
		}
	}
}
