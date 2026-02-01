package output

import (
	"fmt"
	"time"
)

// Warning represents a structured warning with code, message, and optional metadata.
type Warning struct {
	Code      Code                   `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// NewWarning creates a new structured warning with the given code and message.
func NewWarning(code Code, message string) *Warning {
	return &Warning{
		Code:      code,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
}

// NewWarningf creates a new warning with a formatted message.
func NewWarningf(code Code, format string, args ...interface{}) *Warning {
	return &Warning{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Timestamp: time.Now().UTC(),
	}
}

// WithDetail adds a metadata field to the warning and returns it for chaining.
func (w *Warning) WithDetail(key string, value interface{}) *Warning {
	if w.Details == nil {
		w.Details = make(map[string]interface{})
	}
	w.Details[key] = value
	return w
}

// WithDetails adds multiple metadata fields to the warning.
func (w *Warning) WithDetails(details map[string]interface{}) *Warning {
	if w.Details == nil {
		w.Details = make(map[string]interface{})
	}
	for k, v := range details {
		w.Details[k] = v
	}
	return w
}

// String returns a human-readable representation of the warning.
func (w *Warning) String() string {
	return fmt.Sprintf("warning: %s", w.Message)
}
