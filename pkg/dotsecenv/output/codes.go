package output

// Code represents a structured error or warning code.
// These are stable string identifiers for machine-readable error handling.
type Code string

// Error codes - grouped by category
const (
	// General errors (exit code 1)
	CodeGeneralError    Code = "GENERAL_ERROR"
	CodeInvalidInput    Code = "INVALID_INPUT"
	CodeOperationFailed Code = "OPERATION_FAILED"
	CodeUsageError      Code = "USAGE_ERROR"

	// Config errors (exit code 2)
	CodeConfigNotFound   Code = "CONFIG_NOT_FOUND"
	CodeConfigInvalid    Code = "CONFIG_INVALID"
	CodeConfigParseError Code = "CONFIG_PARSE_ERROR"
	CodeConfigSaveError  Code = "CONFIG_SAVE_ERROR"

	// Vault errors (exit code 3)
	CodeVaultNotFound    Code = "VAULT_NOT_FOUND"
	CodeVaultLoadError   Code = "VAULT_LOAD_ERROR"
	CodeVaultSaveError   Code = "VAULT_SAVE_ERROR"
	CodeVaultEmpty       Code = "VAULT_EMPTY"
	CodeVaultLocked      Code = "VAULT_LOCKED"
	CodeVaultReadOnly    Code = "VAULT_READ_ONLY"
	CodeSecretNotFound   Code = "SECRET_NOT_FOUND"
	CodeSecretNoValues   Code = "SECRET_NO_VALUES"
	CodeIdentityNotFound Code = "IDENTITY_NOT_FOUND"

	// GPG errors (exit code 4)
	CodeGPGError         Code = "GPG_ERROR"
	CodeGPGKeyNotFound   Code = "GPG_KEY_NOT_FOUND"
	CodeGPGDecryptFailed Code = "GPG_DECRYPT_FAILED"
	CodeGPGEncryptFailed Code = "GPG_ENCRYPT_FAILED"
	CodeGPGSignFailed    Code = "GPG_SIGN_FAILED"
	CodeGPGVerifyFailed  Code = "GPG_VERIFY_FAILED"

	// Auth errors (exit code 5)
	CodeAuthError Code = "AUTH_ERROR"

	// Validation errors (exit code 6)
	CodeValidationError  Code = "VALIDATION_ERROR"
	CodeSignatureInvalid Code = "SIGNATURE_INVALID"
	CodeHashMismatch     Code = "HASH_MISMATCH"

	// Fingerprint errors (exit code 7)
	CodeFingerprintRequired Code = "FINGERPRINT_REQUIRED"

	// Access denied errors (exit code 8)
	CodeAccessDenied       Code = "SECRET_ACCESS_DENIED"
	CodeIdentityNotInVault Code = "IDENTITY_NOT_IN_VAULT"

	// Algorithm errors (exit code 9)
	CodeAlgorithmNotAllowed Code = "ALGORITHM_NOT_ALLOWED"
	CodeAlgorithmWeak       Code = "ALGORITHM_WEAK"
)

// Warning codes
const (
	CodeWarnGeneric          Code = "WARN_GENERIC"
	CodeWarnFallbackValue    Code = "WARN_FALLBACK_VALUE"
	CodeWarnIgnoringConfig   Code = "WARN_IGNORING_CONFIG"
	CodeWarnVaultNotInConfig Code = "WARN_VAULT_NOT_IN_CONFIG"
	CodeWarnFlagIgnored      Code = "WARN_FLAG_IGNORED"
	CodeWarnFlagConflict     Code = "WARN_FLAG_CONFLICT"
	CodeWarnSelfRevoke       Code = "WARN_SELF_REVOKE"
	CodeWarnIdentityNotFound Code = "WARN_IDENTITY_NOT_FOUND"
	CodeWarnDecodeFailure    Code = "WARN_DECODE_FAILURE"
	CodeWarnDecryptFailure   Code = "WARN_DECRYPT_FAILURE"
	CodeWarnDeprecated       Code = "WARN_DEPRECATED"
	CodeWarnVaultLoadError   Code = "WARN_VAULT_LOAD_ERROR"
)

// IsWarning returns true if the code is a warning code.
func (c Code) IsWarning() bool {
	switch c {
	case CodeWarnGeneric, CodeWarnFallbackValue, CodeWarnIgnoringConfig,
		CodeWarnVaultNotInConfig, CodeWarnFlagIgnored, CodeWarnFlagConflict,
		CodeWarnSelfRevoke, CodeWarnIdentityNotFound, CodeWarnDecodeFailure,
		CodeWarnDecryptFailure, CodeWarnDeprecated, CodeWarnVaultLoadError:
		return true
	default:
		return false
	}
}

// String returns the string representation of the code.
func (c Code) String() string {
	return string(c)
}
