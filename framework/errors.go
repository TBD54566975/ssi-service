package framework

import "github.com/pkg/errors"

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

// SafeError is used to pass an error during the request through the service with
// web specific context. 'Safe' here means that the error messages do not include
// any sensitive information and can be sent straight back to the requester
type SafeError struct {
	Err        error
	StatusCode int
	Fields     []FieldError
}

// SafeError implements the `error` interface. It uses the default message of the
// wrapped error. This is what will be shown in a service's logs
func (err *SafeError) Error() string {
	return err.Err.Error()
}

// NewRequestError wraps a provided error with an HTTP status code. This function should be used
// when handlers encounter expected errors.
func NewRequestError(err error, statusCode int) error {
	return &SafeError{err, statusCode, nil}
}

// shutdown is a type used to help with graceful shutdown of a service.
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

// isShutdown checks to see if the shutdown error is contained in
// the specified error value.
func IsShutdown(err error) bool {
	if _, ok := errors.Cause(err).(*shutdown); ok {
		return true
	}

	return false
}
