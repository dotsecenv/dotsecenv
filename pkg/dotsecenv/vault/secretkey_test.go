package vault

import (
	"testing"
)

func TestParseSecretKey_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantNorm string
		wantNs   bool // whether it should have a namespace
	}{
		// Namespaced keys - case insensitivity
		{"lowercase both", "myns::mykey", "myns::MYKEY", true},
		{"uppercase both", "MYNS::MYKEY", "myns::MYKEY", true},
		{"mixed case", "MyNs::MyKey", "myns::MYKEY", true},
		{"with numbers", "ns1::KEY2", "ns1::KEY2", true},
		{"underscores in namespace", "my_ns::KEY", "my_ns::KEY", true},
		{"underscores in key", "ns::MY_KEY", "ns::MY_KEY", true},
		{"underscores in both", "my_ns::MY_KEY", "my_ns::MY_KEY", true},
		{"leading underscore in key", "ns::_KEY", "ns::_KEY", true},
		{"two consecutive underscores", "ns::A__B", "ns::A__B", true},
		{"two consecutive in namespace", "my__ns::KEY", "my__ns::KEY", true},
		{"complex valid", "prod_db_1::API_KEY_V2", "prod_db_1::API_KEY_V2", true},

		// Non-namespaced keys (simple)
		{"simple key", "DATABASE_URL", "DATABASE_URL", false},
		{"simple lowercase", "database_url", "DATABASE_URL", false},
		{"simple mixed case", "Database_Url", "DATABASE_URL", false},
		{"simple with numbers", "KEY1", "KEY1", false},
		{"simple leading underscore", "_KEY", "_KEY", false},
		{"simple two underscores", "A__B", "A__B", false},

		// Edge cases
		{"whitespace trimmed", "  ns::KEY  ", "ns::KEY", true},
		{"single letter ns", "a::KEY", "a::KEY", true},
		{"single letter key", "ns::A", "ns::A", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, err := ParseSecretKey(tt.input)
			if err != nil {
				t.Errorf("ParseSecretKey(%q) unexpected error: %v", tt.input, err)
				return
			}
			if sk.String() != tt.wantNorm {
				t.Errorf("ParseSecretKey(%q).String() = %q, want %q", tt.input, sk.String(), tt.wantNorm)
			}
			if sk.IsNamespaced() != tt.wantNs {
				t.Errorf("ParseSecretKey(%q).IsNamespaced() = %v, want %v", tt.input, sk.IsNamespaced(), tt.wantNs)
			}
		})
	}
}

func TestParseSecretKey_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		// Empty and format issues
		{"empty string", ""},
		{"only whitespace", "   "},
		{"empty namespace", "::KEY"},
		{"empty key name", "ns::"},
		{"multiple separators", "ns::key::extra"},
		{"only separator", "::"},

		// Namespace validation failures
		{"namespace purely numeric", "123::KEY"},
		{"namespace only underscores", "__::KEY"},
		{"namespace triple underscore", "my___ns::KEY"},
		{"namespace ends with underscore", "ns_::KEY"},
		{"namespace starts with underscore", "_ns::KEY"},
		{"namespace starts with number", "1ns::KEY"},
		{"namespace has special char", "my-ns::KEY"},
		{"namespace has space", "my ns::KEY"},

		// Key name validation failures
		{"key purely numeric", "ns::123"},
		{"key only underscores", "ns::__"},
		{"key triple underscore", "ns::A___B"},
		{"key ends with underscore", "ns::KEY_"},
		{"key starts with number", "ns::1KEY"},
		{"key has special char", "ns::KEY-NAME"},
		{"key has space", "ns::KEY NAME"},
		{"key single underscore suffix", "ns::A_"},

		// Simple key validation failures
		{"simple purely numeric", "123"},
		{"simple only underscores", "__"},
		{"simple triple underscore", "A___B"},
		{"simple ends underscore", "KEY_"},
		{"simple starts with number", "1KEY"},
		{"simple special char", "KEY-NAME"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, err := ParseSecretKey(tt.input)
			if err == nil {
				t.Errorf("ParseSecretKey(%q) expected error, got nil (normalized: %q)", tt.input, sk.String())
			}
		})
	}
}

func TestNormalizeSecretKey(t *testing.T) {
	tests := []struct {
		input    string
		wantNorm string
		wantErr  bool
	}{
		{"myns::KEY", "myns::KEY", false},
		{"MYNS::key", "myns::KEY", false},
		{"MyNs::MyKey", "myns::MYKEY", false},
		{"DATABASE_URL", "DATABASE_URL", false},
		{"database_url", "DATABASE_URL", false},
		{"", "", true},
		{"ns::KEY_", "", true},
		{"123::KEY", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			norm, err := NormalizeSecretKey(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NormalizeSecretKey(%q) expected error, got %q", tt.input, norm)
				}
				return
			}
			if err != nil {
				t.Errorf("NormalizeSecretKey(%q) unexpected error: %v", tt.input, err)
				return
			}
			if norm != tt.wantNorm {
				t.Errorf("NormalizeSecretKey(%q) = %q, want %q", tt.input, norm, tt.wantNorm)
			}
		})
	}
}

func TestCompareSecretKeys(t *testing.T) {
	tests := []struct {
		key1, key2 string
		want       bool
	}{
		// Same keys, different cases
		{"myns::KEY", "MYNS::key", true},
		{"myns::KEY", "myns::KEY", true},
		{"DATABASE_URL", "database_url", true},
		{"DATABASE_URL", "DATABASE_URL", true},

		// Different keys
		{"ns1::KEY", "ns2::KEY", false},
		{"ns::KEY1", "ns::KEY2", false},
		{"DATABASE_URL", "API_KEY", false},

		// Namespaced vs non-namespaced
		{"ns::KEY", "KEY", false},
		{"default::KEY", "KEY", false},

		// Invalid keys - fallback to case-insensitive string compare
		{"invalid_key_", "INVALID_KEY_", true}, // both invalid, but equal ignoring case
		{"ns::KEY_", "ns::key_", true},         // both invalid
		{"ns::KEY", "ns::KEY_", false},         // one valid, one invalid
	}

	for _, tt := range tests {
		t.Run(tt.key1+"_vs_"+tt.key2, func(t *testing.T) {
			if got := CompareSecretKeys(tt.key1, tt.key2); got != tt.want {
				t.Errorf("CompareSecretKeys(%q, %q) = %v, want %v", tt.key1, tt.key2, got, tt.want)
			}
		})
	}
}

func TestIsValidSecretKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"myns::KEY", true},
		{"DATABASE_URL", true},
		{"ns::_KEY", true},
		{"", false},
		{"ns::KEY_", false},
		{"123::KEY", false},
		{"ns::123", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := IsValidSecretKey(tt.key); got != tt.want {
				t.Errorf("IsValidSecretKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestSecretKey_IsNamespaced(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"ns::KEY", true},
		{"my_app::DATABASE_URL", true},
		{"DATABASE_URL", false},
		{"API_KEY", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			sk, err := ParseSecretKey(tt.input)
			if err != nil {
				t.Fatalf("ParseSecretKey(%q) error: %v", tt.input, err)
			}
			if got := sk.IsNamespaced(); got != tt.want {
				t.Errorf("SecretKey(%q).IsNamespaced() = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatSecretKeyError(t *testing.T) {
	_, err := ParseSecretKey("ns::KEY_")
	if err == nil {
		t.Fatal("expected error")
	}

	formatted := FormatSecretKeyError(err)
	if formatted == "" {
		t.Error("FormatSecretKeyError returned empty string")
	}

	// Should contain usage help
	if !contains(formatted, "namespace::KEY_NAME") {
		t.Error("FormatSecretKeyError should contain format example")
	}
	if !contains(formatted, "Namespace rules:") {
		t.Error("FormatSecretKeyError should contain namespace rules")
	}
	if !contains(formatted, "Key name rules:") {
		t.Error("FormatSecretKeyError should contain key name rules")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
