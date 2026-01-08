package vault

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateHeaderMarker(t *testing.T) {
	tests := []struct {
		name    string
		marker  string
		wantErr bool
	}{
		{
			name:    "valid marker",
			marker:  "# === VAULT HEADER ===",
			wantErr: false,
		},
		{
			name:    "invalid marker",
			marker:  "not a valid marker",
			wantErr: true,
		},
		{
			name:    "empty marker",
			marker:  "",
			wantErr: true,
		},
		{
			name:    "old v1 marker (now invalid)",
			marker:  "# === VAULT HEADER v1 ===",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaderMarker(tt.marker)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHeaderMarker() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDetectVersionFromJSON(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantVersion int
		wantErr     bool
	}{
		{
			name:        "v1 json",
			json:        `{"version":1,"identities":[]}`,
			wantVersion: 1,
			wantErr:     false,
		},
		{
			name:        "v2 json",
			json:        `{"version":2,"identities":{}}`,
			wantVersion: 2,
			wantErr:     false,
		},
		{
			name:        "invalid json prefix",
			json:        `{"identities":{}}`,
			wantVersion: 0,
			wantErr:     true,
		},
		{
			name:        "too short",
			json:        `{"v":1}`,
			wantVersion: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detectVersionFromJSON([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("detectVersionFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantVersion {
				t.Errorf("detectVersionFromJSON() = %v, want %v", got, tt.wantVersion)
			}
		})
	}
}

func TestMarshalHeaderV1(t *testing.T) {
	h := &Header{
		Version: 1,
		Identities: map[string]int{
			"FP1": 4,
			"FP2": 5,
		},
		Secrets: map[string]SecretIndex{
			"SEC1": {Definition: 6, Values: []int{7}},
		},
	}

	data, err := MarshalHeaderV1(h)
	if err != nil {
		t.Fatalf("MarshalHeaderV1 failed: %v", err)
	}

	// V1 format should have identities as array of arrays
	str := string(data)
	if !strings.Contains(str, `"identities":[`) {
		t.Errorf("expected array format for identities in v1, got: %s", str)
	}
	if strings.Contains(str, `"identities":{`) {
		t.Errorf("v1 should not have dict format for identities, got: %s", str)
	}
}

func TestMarshalHeaderV2(t *testing.T) {
	h := &Header{
		Version: 2,
		Identities: map[string]int{
			"FP1": 4,
			"FP2": 5,
		},
		Secrets: map[string]SecretIndex{
			"SEC1": {Definition: 6, Values: []int{7}},
		},
	}

	data, err := MarshalHeaderV2(h)
	if err != nil {
		t.Fatalf("MarshalHeaderV2 failed: %v", err)
	}

	// V2 format should have identities as dict
	str := string(data)
	if !strings.Contains(str, `"identities":{`) {
		t.Errorf("expected dict format for identities in v2, got: %s", str)
	}
	if strings.Contains(str, `"identities":[`) {
		t.Errorf("v2 should not have array format for identities, got: %s", str)
	}
}

func TestUnmarshalHeaderV1(t *testing.T) {
	// V1 format with array of arrays
	data := []byte(`{"version":1,"identities":[["FP1",4],["FP2",5]],"secrets":{"SEC1":{"secret":6,"values":[7]}}}`)

	h, err := UnmarshalHeaderV1(data)
	if err != nil {
		t.Fatalf("UnmarshalHeaderV1 failed: %v", err)
	}

	if h.Version != 1 {
		t.Errorf("expected version 1, got %d", h.Version)
	}
	if len(h.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(h.Identities))
	}
	if h.Identities["FP1"] != 4 {
		t.Errorf("expected FP1 at line 4, got %d", h.Identities["FP1"])
	}
}

func TestUnmarshalHeaderV2(t *testing.T) {
	// V2 format with dict
	data := []byte(`{"version":2,"identities":{"FP1":4,"FP2":5},"secrets":{"SEC1":{"secret":6,"values":[7]}}}`)

	h, err := UnmarshalHeaderV2(data)
	if err != nil {
		t.Fatalf("UnmarshalHeaderV2 failed: %v", err)
	}

	if h.Version != 2 {
		t.Errorf("expected version 2, got %d", h.Version)
	}
	if len(h.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(h.Identities))
	}
	if h.Identities["FP1"] != 4 {
		t.Errorf("expected FP1 at line 4, got %d", h.Identities["FP1"])
	}
}

func TestDetectVaultVersion(t *testing.T) {
	// Test with v1 fixture
	v1Path := filepath.Join("testdata", "vault_v1.jsonl")
	version, err := DetectVaultVersion(v1Path)
	if err != nil {
		t.Fatalf("DetectVaultVersion(v1) failed: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1 for v1 vault, got %d", version)
	}

	// Test with v2 fixture
	v2Path := filepath.Join("testdata", "vault_v2.jsonl")
	version, err = DetectVaultVersion(v2Path)
	if err != nil {
		t.Fatalf("DetectVaultVersion(v2) failed: %v", err)
	}
	if version != 2 {
		t.Errorf("expected version 2 for v2 vault, got %d", version)
	}

	// Test with non-existent file
	version, err = DetectVaultVersion("/nonexistent/vault")
	if err != nil {
		t.Fatalf("DetectVaultVersion(nonexistent) should not error: %v", err)
	}
	if version != 0 {
		t.Errorf("expected version 0 for non-existent vault, got %d", version)
	}
}

func TestReadV1Vault(t *testing.T) {
	// Copy v1 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v1Data, err := os.ReadFile(filepath.Join("testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v1Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Read with Reader
	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if r.Version() != 1 {
		t.Errorf("expected version 1, got %d", r.Version())
	}

	fps := r.ListIdentityFingerprints()
	if len(fps) != 2 {
		t.Errorf("expected 2 fingerprints, got %d", len(fps))
	}

	keys := r.ListSecretKeys()
	if len(keys) != 1 {
		t.Errorf("expected 1 secret key, got %d", len(keys))
	}
}

func TestReadV2Vault(t *testing.T) {
	// Copy v2 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v2Data, err := os.ReadFile(filepath.Join("testdata", "vault_v2.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v2 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v2Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Read with Reader
	r, err := NewReader(vaultPath)
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if r.Version() != 2 {
		t.Errorf("expected version 2, got %d", r.Version())
	}

	fps := r.ListIdentityFingerprints()
	if len(fps) != 2 {
		t.Errorf("expected 2 fingerprints, got %d", len(fps))
	}
}

func TestUpgradeV1ToV2(t *testing.T) {
	// Copy v1 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v1Data, err := os.ReadFile(filepath.Join("testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v1Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Open with Writer
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	if w.Version() != 1 {
		t.Errorf("expected initial version 1, got %d", w.Version())
	}

	// Read vault data before upgrade
	vaultBefore, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault failed: %v", err)
	}

	// Perform upgrade
	upgraded, err := CheckAndUpgradeVault(w, vaultPath, false)
	if err != nil {
		t.Fatalf("CheckAndUpgradeVault failed: %v", err)
	}
	if !upgraded {
		t.Error("expected vault to be upgraded")
	}

	// Reload and verify
	if err := w.Reload(); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if w.Version() != 2 {
		t.Errorf("expected version 2 after upgrade, got %d", w.Version())
	}

	// Verify data integrity after upgrade
	vaultAfter, err := w.ReadVault()
	if err != nil {
		t.Fatalf("ReadVault after upgrade failed: %v", err)
	}

	if len(vaultAfter.Identities) != len(vaultBefore.Identities) {
		t.Errorf("identity count mismatch: before=%d, after=%d",
			len(vaultBefore.Identities), len(vaultAfter.Identities))
	}
	if len(vaultAfter.Secrets) != len(vaultBefore.Secrets) {
		t.Errorf("secret count mismatch: before=%d, after=%d",
			len(vaultBefore.Secrets), len(vaultAfter.Secrets))
	}

	// Verify file on disk has new marker format
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read upgraded vault: %v", err)
	}
	if !strings.HasPrefix(string(data), HeaderMarker) {
		t.Errorf("upgraded vault should have marker %q, got: %s", HeaderMarker, string(data[:50]))
	}
}

func TestStrictModeNoUpgrade(t *testing.T) {
	// Copy v1 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v1Data, err := os.ReadFile(filepath.Join("testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v1Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Open with Writer
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Check with strict mode - should not upgrade
	upgraded, err := CheckAndUpgradeVault(w, vaultPath, true)
	if err != nil {
		t.Fatalf("CheckAndUpgradeVault failed: %v", err)
	}
	if upgraded {
		t.Error("strict mode should not upgrade vault")
	}

	// Verify file unchanged (still has v1 content in JSON)
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault: %v", err)
	}
	if !strings.Contains(string(data), `"version":1`) {
		t.Errorf("vault should still have version 1 in header JSON in strict mode")
	}
}

func TestUpgradeIdempotent(t *testing.T) {
	// Copy v2 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v2Data, err := os.ReadFile(filepath.Join("testdata", "vault_v2.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v2 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v2Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Open with Writer
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Already at latest - should not upgrade
	upgraded, err := CheckAndUpgradeVault(w, vaultPath, false)
	if err != nil {
		t.Fatalf("CheckAndUpgradeVault failed: %v", err)
	}
	if upgraded {
		t.Error("already at latest version, should not upgrade")
	}
}

func TestNewVaultUsesLatestVersion(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	// Create new vault
	w, err := NewWriter(vaultPath)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	if w.Version() != LatestFormatVersion {
		t.Errorf("new vault should use latest version %d, got %d",
			LatestFormatVersion, w.Version())
	}

	// Verify file on disk
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault: %v", err)
	}

	if !strings.HasPrefix(string(data), HeaderMarker) {
		t.Errorf("new vault should have marker %q, got: %s", HeaderMarker, string(data[:50]))
	}
}

func TestManagerAutoUpgrade(t *testing.T) {
	// Copy v1 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v1Data, err := os.ReadFile(filepath.Join("testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v1Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Capture stderr to verify warning
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Open with Manager (non-strict mode)
	m := NewManager(vaultPath, false)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	// Restore stderr
	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	stderr := buf.String()

	// Verify warning was printed
	if !strings.Contains(stderr, "warning") {
		t.Errorf("expected warning in stderr, got: %s", stderr)
	}
	if !strings.Contains(stderr, "upgraded") {
		t.Errorf("expected upgrade notice in stderr, got: %s", stderr)
	}

	// Verify vault was upgraded
	if m.Version() != LatestFormatVersion {
		t.Errorf("vault should be at latest version %d, got %d",
			LatestFormatVersion, m.Version())
	}

	// Verify data is accessible
	vault := m.Get()
	if len(vault.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(vault.Identities))
	}
}

func TestManagerStrictModeNoUpgrade(t *testing.T) {
	// Copy v1 fixture to temp dir
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "vault")

	v1Data, err := os.ReadFile(filepath.Join("testdata", "vault_v1.jsonl"))
	if err != nil {
		t.Fatalf("failed to read v1 fixture: %v", err)
	}
	if err := os.WriteFile(vaultPath, v1Data, 0600); err != nil {
		t.Fatalf("failed to write vault: %v", err)
	}

	// Open with Manager (strict mode)
	m := NewManager(vaultPath, true)
	if err := m.OpenAndLock(); err != nil {
		t.Fatalf("OpenAndLock failed: %v", err)
	}
	defer func() { _ = m.Unlock() }()

	// Verify vault is NOT upgraded (still v1)
	if m.Version() != 1 {
		t.Errorf("strict mode should not upgrade, expected version 1, got %d", m.Version())
	}

	// Verify data is still accessible
	vault := m.Get()
	if len(vault.Identities) != 2 {
		t.Errorf("expected 2 identities, got %d", len(vault.Identities))
	}
}

func TestHeaderMarkerForVersion(t *testing.T) {
	// HeaderMarkerForVersion now returns a constant marker regardless of version
	tests := []struct {
		version  int
		expected string
	}{
		{1, HeaderMarker},
		{2, HeaderMarker},
		{10, HeaderMarker},
	}

	for _, tt := range tests {
		got := HeaderMarkerForVersion(tt.version)
		if got != tt.expected {
			t.Errorf("HeaderMarkerForVersion(%d) = %q, want %q", tt.version, got, tt.expected)
		}
	}
}
