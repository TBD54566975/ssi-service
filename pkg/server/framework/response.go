package framework

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Respond convert a Go value to JSON and sends it to the client.
func Respond(c *gin.Context, data any, statusCode int) {
	// check if the data is an error
	var err error
	var ok bool
	if err, ok = data.(error); ok && err != nil {
		// if the error isn't a `SafeError`, it's not safe to send back the error
		// message as is because it may contain sensitive data. Send back a generic
		// 500.
		var webErr *SafeError
		if ok = errors.As(errors.Cause(err), &webErr); !ok {
			statusCode = http.StatusInternalServerError
			logrus.WithError(err).Error("unsafe error")
			webErr.Err = errors.New("error processing request")
		}
		c.PureJSON(statusCode, webErr.Errors())
		return
	}

	// if there's no payload to marshal, set the status code of the response and return
	if statusCode == http.StatusNoContent {
		c.Status(statusCode)
		return
	}

	// respond with pretty JSON
	c.IndentedJSON(statusCode, data)
}

// LoggingRespondError sends an error response back to the client as a safe error
func LoggingRespondError(c *gin.Context, err error, statusCode int) {
	requestErr := newRequestError(err, statusCode)
	logrus.WithError(err).Error(requestErr.Error())
	Respond(c, requestErr, statusCode)
}

// LoggingRespondErrMsg sends an error response back to the client as a safe error from a msg
func LoggingRespondErrMsg(c *gin.Context, errMsg string, statusCode int) {
	LoggingRespondError(c, errors.New(errMsg), statusCode)
}

// LoggingRespondErrWithMsg sends an error response back to the client as a safe error from an error and msg
func LoggingRespondErrWithMsg(c *gin.Context, err error, errMsg string, statusCode int) {
	LoggingRespondError(c, errors.Wrap(err, errMsg), statusCode)
}
