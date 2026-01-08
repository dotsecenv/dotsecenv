package main_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Helper to extract raw secret value from vault file (JSONL format)
func getLatestSecretValue(t *testing.T, vaultPath string, secretKey string) string {
	file, err := os.Open(vaultPath)
	if err != nil {
		t.Fatalf("failed to open vault file: %v", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to scan vault: %v", err)
	}

	if len(lines) < 3 {
		t.Fatalf("vault file too short")
	}

	// Parse header (line 2, 0-indexed line 1)
	// Note: identities are now stored as [[fingerprint, line], ...] array format
	var header struct {
		Version    int              `json:"version"`
		Identities [][2]interface{} `json:"identities"` // [[fingerprint, line], ...]
		Secrets    map[string]struct {
			Definition int   `json:"secret"` // renamed from "definition" to "secret"
			Values     []int `json:"values"`
		} `json:"secrets"`
	}

	if err := json.Unmarshal([]byte(lines[1]), &header); err != nil {
		t.Fatalf("failed to parse vault header: %v", err)
	}

	secretIdx, exists := header.Secrets[secretKey]
	if !exists {
		t.Fatalf("secret not found in header: %s", secretKey)
	}

	if len(secretIdx.Values) == 0 {
		t.Fatalf("secret has no values: %s", secretKey)
	}

	// Get the latest value (last line number in the values array)
	latestLineNum := secretIdx.Values[len(secretIdx.Values)-1]
	if latestLineNum < 1 || latestLineNum > len(lines) {
		t.Fatalf("invalid line number for secret value: %d", latestLineNum)
	}

	// Parse the value entry
	var entry struct {
		Type string `json:"type"`
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}

	if err := json.Unmarshal([]byte(lines[latestLineNum-1]), &entry); err != nil {
		t.Fatalf("failed to parse value entry at line %d: %v", latestLineNum, err)
	}

	if entry.Type != "value" {
		t.Fatalf("expected value entry, got: %s", entry.Type)
	}

	return entry.Data.Value
}

func TestIssue_SelfRevokeAddsGPGKey(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, err := os.MkdirTemp("", "dotsecenv-repro-gpg")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(gpgHome) }()

	// Create two users
	fpA := generateKey(t, gpgHome, "User A", "usera@example.com")
	fpB := generateKey(t, gpgHome, "User B", "userb@example.com")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
`, vaultPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}

	envA := []string{"GNUPGHOME=" + gpgHome, "DOTSECENV_FINGERPRINT=" + fpA}

	// Init
	_, _, _ = runCmdWithEnv(envA, "init", "vault", "-v", vaultPath)
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "vault", "identity", "add", "-v", "1", fpA)
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "vault", "identity", "add", "-v", "1", fpB)

	// 1. User A puts secret
	cmd := exec.Command(binaryPath, "-c", configPath, "secret", "put", "SEC1")
	cmd.Env = append(filteredEnv(), envA...)
	cmd.Stdin = strings.NewReader("secret_value_1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("secret put failed: %v\n%s", err, out)
	}

	// 2. User A shares with User B
	if _, _, err := runCmdWithEnv(envA, "-c", configPath, "secret", "share", "SEC1", fpB); err != nil {
		t.Fatalf("secret share failed: %v", err)
	}

	// 3. User A revokes User A (Self)
	stdoutRevoke, stderrRevoke, err := runCmdWithEnv(envA, "-c", configPath, "secret", "revoke", "SEC1", fpA)
	if err != nil {
		t.Fatalf("secret revoke failed: %v\nSTDERR: %s", err, stderrRevoke)
	}
	t.Logf("Revoke STDERR: %s", stderrRevoke)
	t.Logf("Revoke STDOUT: %s", stdoutRevoke)

	// 4. Verify User A gets the older value via fallback (with warning)
	// Since A was revoked from latest, but had access to previous, it should return previous.
	_, stderr, err := runCmdWithEnv(envA, "-c", configPath, "secret", "get", "SEC1")
	if err != nil {
		t.Errorf("CLI failed to get secret (fallback expected): %v\nSTDERR: %s", err, stderr)
	} else {
		if !strings.Contains(stderr, "warning: returning older value") {
			t.Errorf("Expected warning about returning older value, got: %s", stderr)
		}
	}

	// 5. Verify recipients using gpg --list-packets
	// This proves if the key was added to the recipient list under the hood
	encryptedBase64 := getLatestSecretValue(t, vaultPath, "SEC1")
	encryptedArmored, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}

	// Check recipients
	listCmd := exec.Command("gpg", "--list-packets")
	listCmd.Env = append(filteredEnv(), "GNUPGHOME="+gpgHome)
	listCmd.Stdin = strings.NewReader(string(encryptedArmored))
	out, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gpg --list-packets failed: %v\n%s", err, out)
	}

	output := string(out)
	// User A Key ID
	// Get A's Key ID (short or long)
	// We have fingerprint fpA. Key ID is usually last 16 chars.
	if len(fpA) < 16 {
		t.Fatalf("invalid fingerprint A: %s", fpA)
	}
	keyIdA := fpA[len(fpA)-16:]

	if strings.Contains(strings.ToUpper(output), strings.ToUpper(keyIdA)) {
		t.Errorf("SECURITY VULNERABILITY: User A's Key ID (%s) found in encrypted message packets!\nOutput:\n%s", keyIdA, output)
	} else {
		t.Logf("User A is NOT in recipients list (Good).")
	}
}

func TestIssue_RevokeWithoutAccess(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not found")
	}

	gpgHome, err := os.MkdirTemp("", "dotsecenv-repro-gpg-2")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(gpgHome) }()

	fpA := generateKey(t, gpgHome, "User A", "usera@example.com")
	fpB := generateKey(t, gpgHome, "User B", "userb@example.com")
	fpC := generateKey(t, gpgHome, "User C", "userc@example.com")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	vaultPath := filepath.Join(tmpDir, "vault")

	configContent := fmt.Sprintf(`
approved_algorithms:
  - algo: RSA
    min_bits: 2048
vault:
  - "%s"
`, vaultPath)
	_ = os.WriteFile(configPath, []byte(configContent), 0600)

	envA := []string{"GNUPGHOME=" + gpgHome, "DOTSECENV_FINGERPRINT=" + fpA}
	envB := []string{"GNUPGHOME=" + gpgHome, "DOTSECENV_FINGERPRINT=" + fpB}

	_, _, _ = runCmdWithEnv(envA, "init", "vault", "-v", vaultPath)
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "vault", "identity", "add", "-v", "1", fpA)
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "vault", "identity", "add", "-v", "1", fpB)
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "vault", "identity", "add", "-v", "1", fpC)

	// 1. A creates secret (v1)
	cmd := exec.Command(binaryPath, "-c", configPath, "secret", "put", "SEC1")
	cmd.Env = append(filteredEnv(), envA...)
	cmd.Stdin = strings.NewReader("v1")
	_ = cmd.Run()

	// 2. Share with B (v1 shared with A, B)
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "secret", "share", "SEC1", fpB)

	// 3. Share with C
	_, _, _ = runCmdWithEnv(envA, "-c", configPath, "secret", "share", "SEC1", fpC)

	// 4. A updates secret (v4) -> Only A has access
	cmd = exec.Command(binaryPath, "-c", configPath, "secret", "put", "SEC1")
	cmd.Env = append(filteredEnv(), envA...)
	cmd.Stdin = strings.NewReader("v4")
	_ = cmd.Run()

	// 5. B tries to revoke C.
	// B has access to v2 and v3.
	// B does NOT have access to v4 (latest).
	// B tries to revoke C from SEC1.
	_, stderr, err := runCmdWithEnv(envB, "-c", configPath, "secret", "revoke", "SEC1", fpC)

	if err == nil {
		t.Errorf("SECURITY VULNERABILITY: User B revoked C from secret SEC1 despite not having access to latest value!")
	} else {
		if strings.Contains(stderr, "access denied") {
			t.Logf("Revoke failed as expected with access denied: %v", err)
		} else {
			t.Errorf("Revoke failed but with unexpected error: %s", stderr)
		}
	}
}
