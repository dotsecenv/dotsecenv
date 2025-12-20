package output

import (
	"encoding/json"
	"io"
)

// Envelope wraps command output in a standardized JSON structure.
// This provides a consistent format for all JSON output with data, warnings, and errors.
type Envelope struct {
	Data     interface{} `json:"data,omitempty"`
	Warnings []*Warning  `json:"warnings,omitempty"`
	Error    *Error      `json:"error,omitempty"`
}

// NewEnvelope creates a new envelope with the given data.
func NewEnvelope(data interface{}) *Envelope {
	return &Envelope{
		Data:     data,
		Warnings: make([]*Warning, 0),
	}
}

// NewErrorEnvelope creates an envelope containing only an error.
func NewErrorEnvelope(err *Error) *Envelope {
	return &Envelope{
		Error:    err,
		Warnings: make([]*Warning, 0),
	}
}

// AddWarning appends a warning to the envelope.
func (e *Envelope) AddWarning(w *Warning) {
	e.Warnings = append(e.Warnings, w)
}

// AddWarnings appends multiple warnings to the envelope.
func (e *Envelope) AddWarnings(warnings []*Warning) {
	e.Warnings = append(e.Warnings, warnings...)
}

// SetData sets the data payload of the envelope.
func (e *Envelope) SetData(data interface{}) {
	e.Data = data
}

// SetError sets the error on the envelope.
func (e *Envelope) SetError(err *Error) {
	e.Error = err
}

// HasWarnings returns true if there are any warnings.
func (e *Envelope) HasWarnings() bool {
	return len(e.Warnings) > 0
}

// HasError returns true if there is an error.
func (e *Envelope) HasError() bool {
	return e.Error != nil
}

// IsSuccess returns true if there is no error.
func (e *Envelope) IsSuccess() bool {
	return e.Error == nil
}

// WriteTo serializes the envelope to a writer as JSON.
func (e *Envelope) WriteTo(w io.Writer, indent bool) error {
	encoder := json.NewEncoder(w)
	if indent {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(e)
}

// MarshalIndent returns the envelope as indented JSON bytes.
func (e *Envelope) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

// Marshal returns the envelope as JSON bytes.
func (e *Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}
