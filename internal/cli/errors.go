package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/dotsecenv/dotsecenv/pkg/dotsecenv/output"
)

// ExitCode represents the exit code for an error.
// This is an alias to the output package for backward compatibility.
type ExitCode = output.ExitCode

// Exit code constants - aliases to output package.
const (
	ExitSuccess             = output.ExitSuccess
	ExitGeneralError        = output.ExitGeneralError
	ExitConfigError         = output.ExitConfigError
	ExitVaultError          = output.ExitVaultError
	ExitGPGError            = output.ExitGPGError
	ExitAuthError           = output.ExitAuthError
	ExitValidationError     = output.ExitValidationError
	ExitFingerprintRequired = output.ExitFingerprintRequired
	ExitAccessDenied        = output.ExitAccessDenied
	ExitAlgorithmNotAllowed = output.ExitAlgorithmNotAllowed
)

// Error represents a CLI error with an exit code.
// Kept for backward compatibility; new code should use output.Error.
type Error struct {
	Message  string
	ExitCode ExitCode
}

// NewError creates a new CLI error.
// For new code, prefer output.NewError with a structured code.
func NewError(message string, code ExitCode) *Error {
	return &Error{
		Message:  message,
		ExitCode: code,
	}
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Message
}

// PrintError prints an error to stderr and returns the exit code.
// Handles both legacy Error and output.Error types.
func PrintError(w io.Writer, err error) ExitCode {
	if err == nil {
		return ExitSuccess
	}

	// Check for new output.Error type first
	if outErr, ok := err.(*output.Error); ok {
		_, _ = fmt.Fprintf(w, "%s\n", outErr.Message)
		return outErr.ExitCode()
	}

	// Check for legacy Error type
	if clierr, ok := err.(*Error); ok {
		if clierr.Message != "" {
			_, _ = fmt.Fprintf(w, "%s\n", clierr.Message)
		}
		return clierr.ExitCode
	}

	// Generic error
	_, _ = fmt.Fprintf(w, "%v\n", err)
	return ExitGeneralError
}

// PrintWarning prints a warning to stderr.
func PrintWarning(w io.Writer, message string) {
	_, _ = fmt.Fprintf(w, "warning: %s\n", message)
}

// PrintSuccess prints a success message to stdout.
func PrintSuccess(w io.Writer, message string) {
	_, _ = fmt.Fprintf(w, "%s\n", message)
}

// ExitWithError exits the program with the given error.
func ExitWithError(err error) {
	code := PrintError(os.Stderr, err)
	os.Exit(int(code))
}
