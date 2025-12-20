package output

import (
	"encoding/json"
	"fmt"
)

// Error represents a structured error with code, message, and optional metadata.
// It implements the standard error interface and supports error chaining.
type Error struct {
	Code    Code                   `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
	Cause   error                  `json:"-"` // Not serialized, for error chaining
}

// NewError creates a new structured error with the given code and message.
func NewError(code Code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// NewErrorf creates a new structured error with a formatted message.
func NewErrorf(code Code, format string, args ...interface{}) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

// WithDetail adds a metadata field to the error and returns the error for chaining.
func (e *Error) WithDetail(key string, value interface{}) *Error {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithDetails adds multiple metadata fields to the error.
func (e *Error) WithDetails(details map[string]interface{}) *Error {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	for k, v := range details {
		e.Details[k] = v
	}
	return e
}

// WithCause wraps an underlying error for error chaining.
func (e *Error) WithCause(cause error) *Error {
	e.Cause = cause
	return e
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *Error) Unwrap() error {
	return e.Cause
}

// ExitCode returns the numeric exit code for CLI use.
func (e *Error) ExitCode() ExitCode {
	return e.Code.GetExitCode()
}

// MarshalJSON provides custom JSON marshaling that includes the exit code.
func (e *Error) MarshalJSON() ([]byte, error) {
	type alias Error
	return json.Marshal(&struct {
		*alias
		ExitCode ExitCode `json:"exit_code"`
	}{
		alias:    (*alias)(e),
		ExitCode: e.ExitCode(),
	})
}

// Is checks if this error matches another error by code.
// This supports errors.Is() for code-based matching.
func (e *Error) Is(target error) bool {
	if t, ok := target.(*Error); ok {
		return e.Code == t.Code
	}
	return false
}
