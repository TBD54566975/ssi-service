package framework

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// Respond convert a Go value to JSON and sends it to the client.
func Respond(c *gin.Context, data any, statusCode int) error {
	// set the status code within the context's request state. Gracefully shutdown if
	// the request state doesn't exist in the context
	v, ok := c.Value(KeyRequestState).(*RequestState)
	if !ok {
		err := NewShutdownError("request state missing from context.")
		c.Set(ShutdownErrorState.String(), err)
		return err
	}

	v.StatusCode = statusCode

	// if there's no payload to marshal, set the status code of the response and return
	if statusCode == http.StatusNoContent {
		c.Status(statusCode)
		return nil
	}

	// respond with pretty JSON
	c.IndentedJSON(statusCode, data)
	return nil
}

// RespondError sends an error response back to the client. If the error is a `SafeError`,
// the error message and fields are sent back to the client. If the error is not a
// `SafeError`, a generic error message is sent back to the client.
// TODO(gabe) use this instead of creating new errors
func RespondError(c *gin.Context, err error) error {
	// if the cause of the error provided is a `SafeError`, construct an ErrorResponse
	// using the contents of SafeError and send it back to the client
	var webErr *SafeError
	if ok := errors.As(errors.Cause(err), &webErr); ok {
		er := ErrorResponse{
			Error:  webErr.Err.Error(),
			Fields: webErr.Fields,
		}
		return Respond(c, er, webErr.StatusCode)
	}

	// if the error isn't a `SafeError`, it's not safe to send back the error
	// message as is because it may contain sensitive data. Send back a generic
	// 500.
	er := ErrorResponse{
		Error: http.StatusText(http.StatusInternalServerError),
	}

	return Respond(c, er, http.StatusInternalServerError)
}
