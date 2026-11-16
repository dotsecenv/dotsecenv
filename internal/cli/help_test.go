package cli

import (
	"bytes"
	"crypto/fips140"
	"encoding/json"
	"strings"
	"testing"
)

func TestPrintVersionJSONCryptoInfo(t *testing.T) {
	var buf bytes.Buffer
	PrintVersionJSON(&buf, "v1.2.3", "abc1234", "2026-01-01T00:00:00Z")

	var got struct {
		Crypto map[string]any `json:"crypto"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}

	if got.Crypto["fips140Enabled"] != fips140.Enabled() {
		t.Errorf("fips140Enabled = %v, want %v", got.Crypto["fips140Enabled"], fips140.Enabled())
	}
	if got.Crypto["fips140Enforced"] != fips140.Enforced() {
		t.Errorf("fips140Enforced = %v, want %v", got.Crypto["fips140Enforced"], fips140.Enforced())
	}

	// The module version is only meaningful for GOFIPS140 builds; test
	// binaries are built without it, so both fields must be absent together.
	_, hasSetting := got.Crypto["GOFIPS140"]
	_, hasModule := got.Crypto["fips140ModuleVersion"]
	if hasSetting != hasModule {
		t.Errorf("GOFIPS140 present=%v but fips140ModuleVersion present=%v", hasSetting, hasModule)
	}
}

func TestFipsMode(t *testing.T) {
	want := "disabled"
	switch {
	case fips140.Enforced():
		want = "enforced"
	case fips140.Enabled():
		want = "enabled"
	}
	if got := fipsMode(); got != want {
		t.Errorf("fipsMode() = %q, want %q", got, want)
	}
}

func TestCryptoStatusMentionsModule(t *testing.T) {
	status := cryptoStatus()
	if fipsBuildSetting() == "" {
		if !strings.Contains(status, "not FIPS validated") {
			t.Errorf("cryptoStatus() = %q, want non-FIPS description", status)
		}
		return
	}
	if !strings.Contains(status, "module "+fips140.Version()) {
		t.Errorf("cryptoStatus() = %q, want module version %q", status, fips140.Version())
	}
}
