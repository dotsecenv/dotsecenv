package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintSuccessOutput_WithConfig(t *testing.T) {
	var buf bytes.Buffer

	printSuccessOutput(&buf, "Test User", "test@example.com", "ED25519", "ABCD1234FINGERPRINT", true)

	output := buf.String()

	// Should show single "Next step" with login command
	if !strings.Contains(output, "Next step - login to dotsecenv:") {
		t.Error("expected 'Next step - login to dotsecenv:' when config exists")
	}
	if !strings.Contains(output, "dotsecenv login ABCD1234FINGERPRINT") {
		t.Error("expected login command with fingerprint")
	}

	// Should NOT suggest init config
	if strings.Contains(output, "dotsecenv init config") {
		t.Error("should not suggest 'dotsecenv init config' when config already exists")
	}
}

func TestPrintSuccessOutput_WithoutConfig(t *testing.T) {
	var buf bytes.Buffer

	printSuccessOutput(&buf, "Test User", "test@example.com", "ED25519", "ABCD1234FINGERPRINT", false)

	output := buf.String()

	// Should show numbered steps
	if !strings.Contains(output, "Next steps:") {
		t.Error("expected 'Next steps:' when no config exists")
	}
	if !strings.Contains(output, "dotsecenv init config") {
		t.Error("expected 'dotsecenv init config' suggestion when no config exists")
	}
	if !strings.Contains(output, "Review the created config, then login:") {
		t.Error("expected review guidance when no config exists")
	}
	if !strings.Contains(output, "dotsecenv login ABCD1234FINGERPRINT") {
		t.Error("expected login command with fingerprint")
	}

	// Should NOT show single "Next step" format
	if strings.Contains(output, "Next step - login to dotsecenv:") {
		t.Error("should not show single next step format when no config exists")
	}
}
