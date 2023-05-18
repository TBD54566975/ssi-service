package framework

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// GetParam is a utility to get a path parameter from context, nil if not found
func GetParam(c *gin.Context, param string) *string {
	got := c.Param(param)
	if got == "" {
		return nil
	}
	// remove leading slash, which is a quirk of gin
	if got[0] == '/' {
		got = got[1:]
	}
	return &got
}

// GetQueryValue is a utility to get a parameter value from the query string, nil if not found
func GetQueryValue(c *gin.Context, param string) *string {
	got, ok := c.GetQuery(param)
	if got == "" || !ok {
		return nil
	}
	return &got
}

// PeekRequestBody reads a request's body without emptying the buffer
func PeekRequestBody(r *http.Request) (string, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return "", errors.Wrap(err, "could not ready request body")
	}
	result := string(bodyBytes)
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return result, nil
}
