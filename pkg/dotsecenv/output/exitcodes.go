package output

// ExitCode represents numeric exit codes for CLI backward compatibility.
// These match the existing exit codes in internal/cli/errors.go.
type ExitCode int

const (
	ExitSuccess             ExitCode = 0
	ExitGeneralError        ExitCode = 1
	ExitConfigError         ExitCode = 2
	ExitVaultError          ExitCode = 3
	ExitGPGError            ExitCode = 4
	ExitAuthError           ExitCode = 5
	ExitValidationError     ExitCode = 6
	ExitFingerprintRequired ExitCode = 7
	ExitAccessDenied        ExitCode = 8
	ExitAlgorithmNotAllowed ExitCode = 9
)

// codeToExitCode maps structured codes to numeric exit codes.
var codeToExitCode = map[Code]ExitCode{
	// General errors (exit code 1)
	CodeGeneralError:    ExitGeneralError,
	CodeInvalidInput:    ExitGeneralError,
	CodeOperationFailed: ExitGeneralError,
	CodeUsageError:      ExitGeneralError,

	// Config errors (exit code 2)
	CodeConfigNotFound:   ExitConfigError,
	CodeConfigInvalid:    ExitConfigError,
	CodeConfigParseError: ExitConfigError,
	CodeConfigSaveError:  ExitConfigError,

	// Vault errors (exit code 3)
	CodeVaultNotFound:    ExitVaultError,
	CodeVaultLoadError:   ExitVaultError,
	CodeVaultSaveError:   ExitVaultError,
	CodeVaultEmpty:       ExitVaultError,
	CodeVaultLocked:      ExitVaultError,
	CodeVaultReadOnly:    ExitVaultError,
	CodeSecretNotFound:   ExitVaultError,
	CodeSecretNoValues:   ExitVaultError,
	CodeIdentityNotFound: ExitVaultError,

	// GPG errors (exit code 4)
	CodeGPGError:         ExitGPGError,
	CodeGPGKeyNotFound:   ExitGPGError,
	CodeGPGDecryptFailed: ExitGPGError,
	CodeGPGEncryptFailed: ExitGPGError,
	CodeGPGSignFailed:    ExitGPGError,
	CodeGPGVerifyFailed:  ExitGPGError,

	// Auth errors (exit code 5)
	CodeAuthError: ExitAuthError,

	// Validation errors (exit code 6)
	CodeValidationError:  ExitValidationError,
	CodeSignatureInvalid: ExitValidationError,
	CodeHashMismatch:     ExitValidationError,

	// Fingerprint errors (exit code 7)
	CodeFingerprintRequired: ExitFingerprintRequired,

	// Access denied errors (exit code 8)
	CodeAccessDenied:       ExitAccessDenied,
	CodeIdentityNotInVault: ExitAccessDenied,

	// Algorithm errors (exit code 9)
	CodeAlgorithmNotAllowed: ExitAlgorithmNotAllowed,
	CodeAlgorithmWeak:       ExitAlgorithmNotAllowed,
}

// exitCodeToCode provides reverse mapping for compatibility helpers.
var exitCodeToCode = map[ExitCode]Code{
	ExitGeneralError:        CodeGeneralError,
	ExitConfigError:         CodeConfigNotFound,
	ExitVaultError:          CodeVaultNotFound,
	ExitGPGError:            CodeGPGError,
	ExitAuthError:           CodeAuthError,
	ExitValidationError:     CodeValidationError,
	ExitFingerprintRequired: CodeFingerprintRequired,
	ExitAccessDenied:        CodeAccessDenied,
	ExitAlgorithmNotAllowed: CodeAlgorithmNotAllowed,
}

// GetExitCode returns the numeric exit code for a structured code.
func (c Code) GetExitCode() ExitCode {
	if exit, ok := codeToExitCode[c]; ok {
		return exit
	}
	return ExitGeneralError
}

// Int returns the integer value of the exit code.
func (e ExitCode) Int() int {
	return int(e)
}

// CodeFromExitCode returns a generic Code for a numeric exit code.
// Used for backward compatibility when converting legacy errors.
func CodeFromExitCode(exitCode ExitCode) Code {
	if code, ok := exitCodeToCode[exitCode]; ok {
		return code
	}
	return CodeGeneralError
}
