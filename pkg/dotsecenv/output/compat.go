package output

import (
	"fmt"
	"io"
	"os"
)

// PrintError writes an error message to the given writer and returns the exit code.
// This provides backward compatibility with the existing cli.PrintError function.
func PrintError(w io.Writer, err error) ExitCode {
	if err == nil {
		return ExitSuccess
	}

	if outErr, ok := err.(*Error); ok {
		_, _ = fmt.Fprintf(w, "%s\n", outErr.Message)
		return outErr.ExitCode()
	}

	// For non-output.Error types, print the error and return general error
	_, _ = fmt.Fprintf(w, "%v\n", err)
	return ExitGeneralError
}

// ExitWithError prints an error and exits with the appropriate code.
// This provides backward compatibility with the existing cli.ExitWithError function.
func ExitWithError(err error) {
	code := PrintError(os.Stderr, err)
	os.Exit(code.Int())
}

// FromLegacyError creates an output.Error from a message and numeric exit code.
// Used for backward compatibility when converting legacy errors.
func FromLegacyError(message string, exitCode ExitCode) *Error {
	code := CodeFromExitCode(exitCode)
	return NewError(code, message)
}

// PrintWarning writes a warning message to the given writer.
// Provides backward compatibility with cli.PrintWarning.
func PrintWarning(w io.Writer, message string) {
	_, _ = fmt.Fprintf(w, "warning: %s\n", message)
}

// NewLegacyError creates an error matching the legacy cli.Error signature.
// This is a convenience function for gradual migration.
//
// Deprecated: Use NewError with a structured Code instead.
func NewLegacyError(message string, exitCode ExitCode) *Error {
	return FromLegacyError(message, exitCode)
}

// ToLegacy returns the message and exit code for backward compatibility.
// This allows the new Error type to be used with code expecting the old format.
func (e *Error) ToLegacy() (string, ExitCode) {
	return e.Message, e.ExitCode()
}
