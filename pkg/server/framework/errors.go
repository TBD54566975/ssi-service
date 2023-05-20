package framework

import (
	"strings"

	"github.com/pkg/errors"
)

// FieldError is used to indicate an error with a field in a request payload.
type FieldError struct {
	Field string `json:"field"`
	Error string `json:"error"`
}

// ErrorResponse is the structure of response error payloads sent back to the requester
// when validation of a request payload fails.
type ErrorResponse struct {
	Error  string       `json:"error"`
	Fields []FieldError `json:"fields,omitempty"`
}

// SafeError is used to pass an error during the request through the server with
// web specific context. 'Safe' here means that the error messages do not include
// any sensitive information and can be sent straight back to the requester
type SafeError struct {
	Err        error
	StatusCode int
	Fields     []FieldError
}

// SafeError implements the `error` interface. It uses the default message of the
// wrapped error. This is what will be shown in a server's logs
func (err *SafeError) Error() string {
	return err.Err.Error()
}

// Errors returns the error message and all field errors as a single error
func (err *SafeError) Errors() string {
	if len(err.Fields) == 0 {
		if safe, ok := err.Err.(*SafeError); ok {
			return safe.Err.Error()
		}
	}
	errs := make([]string, 0, len(err.Fields)+1)
	for _, field := range err.Fields {
		errs = append(errs, field.Field)
	}
	return errors.WithStack(err.Err).Error() + ": " + strings.Join(errs, ", ")
}

// newRequestError wraps a provided error with an HTTP status code. This function should be used
// when router encounter expected errors.
func newRequestError(err error, statusCode int) error {
	return &SafeError{err, statusCode, nil}
}

// shutdown is a type used to help with graceful shutdown of a server.
type shutdown struct {
	Message string
}

// shutdown implements the Error interface
func (s *shutdown) Error() string {
	return s.Message
}

// NewShutdownError returns an error that causes the framework to signal.
// a graceful shutdown
func NewShutdownError(message string) error {
	return &shutdown{message}
}

// IsShutdown checks to see if the shutdown error is contained in
// the specified error value.
func IsShutdown(err error) bool {
	var shutdownErr *shutdown
	return errors.As(errors.Cause(err), &shutdownErr)
}
