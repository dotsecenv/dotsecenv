package vault

import (
	"testing"
)

func TestNewVault(t *testing.T) {
	v := NewVault()
	if v.Identities == nil {
		t.Error("NewVault should initialize Identities")
	}
	if v.Secrets == nil {
		t.Error("NewVault should initialize Secrets")
	}
}

func TestVault_GetIdentityByFingerprint(t *testing.T) {
	v := Vault{
		Identities: []Identity{
			{Fingerprint: "fp1", UID: "user1"},
			{Fingerprint: "fp2", UID: "user2"},
		},
	}

	id := v.GetIdentityByFingerprint("fp1")
	if id == nil || id.UID != "user1" {
		t.Error("failed to get identity fp1")
	}

	id = v.GetIdentityByFingerprint("fp3")
	if id != nil {
		t.Error("should return nil for non-existent identity")
	}
}

func TestVault_GetSecretByKey(t *testing.T) {
	v := Vault{
		Secrets: []Secret{
			{Key: "secret1"},
			{Key: "secret2"},
		},
	}

	s := v.GetSecretByKey("secret1")
	if s == nil || s.Key != "secret1" {
		t.Error("failed to get secret1")
	}

	s = v.GetSecretByKey("secret3")
	if s != nil {
		t.Error("should return nil for non-existent secret")
	}
}

func TestVault_AccessControl(t *testing.T) {
	v := Vault{
		Secrets: []Secret{
			{
				Key: "secret1",
				Values: []SecretValue{
					{Value: "v1", AvailableTo: []string{"user1"}},
					{Value: "v2", AvailableTo: []string{"user2"}},
				},
			},
		},
	}

	tests := []struct {
		name        string
		fingerprint string
		wantAccess  bool
	}{
		{"user1 access", "user1", true},
		{"user2 access", "user2", true},
		{"user3 no access", "user3", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v.CanIdentityAccessSecret(tt.fingerprint, "secret1"); got != tt.wantAccess {
				t.Errorf("CanIdentityAccessSecret(%s) = %v, want %v", tt.fingerprint, got, tt.wantAccess)
			}
		})
	}
}

func TestVault_GetAccessibleSecretValue(t *testing.T) {
	v := Vault{
		Secrets: []Secret{
			{
				Key: "secret1",
				Values: []SecretValue{
					{Value: "old", AvailableTo: []string{"user1"}},
					{Value: "new", AvailableTo: []string{"user2"}},
				},
			},
		},
	}

	// Test Strict Mode
	t.Run("Strict Mode", func(t *testing.T) {
		// User2 should see "new"
		val := v.GetAccessibleSecretValue("user2", "secret1", true)
		if val == nil || val.Value != "new" {
			t.Error("user2 should see 'new' in strict mode")
		}

		// User1 should see nil because they don't have access to "new" (latest)
		val = v.GetAccessibleSecretValue("user1", "secret1", true)
		if val != nil {
			t.Error("user1 should not see anything in strict mode (only has access to old)")
		}
	})

	// Test Non-Strict Mode (Fallback)
	t.Run("Non-Strict Mode", func(t *testing.T) {
		// User2 should see "new"
		val := v.GetAccessibleSecretValue("user2", "secret1", false)
		if val == nil || val.Value != "new" {
			t.Error("user2 should see 'new'")
		}

		// User1 should see "old" (fallback)
		val = v.GetAccessibleSecretValue("user1", "secret1", false)
		if val == nil || val.Value != "old" {
			t.Error("user1 should see 'old'")
		}
	})
}

func TestSecret_IsDeleted(t *testing.T) {
	tests := []struct {
		name    string
		secret  Secret
		deleted bool
	}{
		{
			name:    "empty values",
			secret:  Secret{Key: "test", Values: []SecretValue{}},
			deleted: false,
		},
		{
			name: "not deleted",
			secret: Secret{
				Key: "test",
				Values: []SecretValue{
					{Value: "v1", AvailableTo: []string{"user1"}},
				},
			},
			deleted: false,
		},
		{
			name: "deleted",
			secret: Secret{
				Key: "test",
				Values: []SecretValue{
					{Value: "v1", AvailableTo: []string{"user1"}},
					{Value: "", AvailableTo: []string{}, Deleted: true},
				},
			},
			deleted: true,
		},
		{
			name: "deleted then recreated is not deleted",
			secret: Secret{
				Key: "test",
				Values: []SecretValue{
					{Value: "v1", AvailableTo: []string{"user1"}},
					{Value: "", AvailableTo: []string{}, Deleted: true},
					{Value: "v2", AvailableTo: []string{"user1"}, Deleted: false},
				},
			},
			deleted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.secret.IsDeleted(); got != tt.deleted {
				t.Errorf("IsDeleted() = %v, want %v", got, tt.deleted)
			}
		})
	}
}

func TestVault_GetAccessibleSecretValue_Deleted(t *testing.T) {
	v := Vault{
		Secrets: []Secret{
			{
				Key: "deleted_secret",
				Values: []SecretValue{
					{Value: "old", AvailableTo: []string{"user1"}},
					{Value: "", AvailableTo: []string{}, Deleted: true},
				},
			},
			{
				Key: "active_secret",
				Values: []SecretValue{
					{Value: "value", AvailableTo: []string{"user1"}},
				},
			},
		},
	}

	t.Run("deleted secret returns nil", func(t *testing.T) {
		// Even though user1 had access to the old value, deleted secret returns nil
		val := v.GetAccessibleSecretValue("user1", "deleted_secret", false)
		if val != nil {
			t.Error("deleted secret should return nil even for user with previous access")
		}

		val = v.GetAccessibleSecretValue("user1", "deleted_secret", true)
		if val != nil {
			t.Error("deleted secret should return nil in strict mode too")
		}
	})

	t.Run("active secret still works", func(t *testing.T) {
		val := v.GetAccessibleSecretValue("user1", "active_secret", false)
		if val == nil || val.Value != "value" {
			t.Error("active secret should be accessible")
		}
	})
}
