package framework

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/dimfeld/httptreemux/v5"
	"github.com/pkg/errors"
)

// GetParam is a utility to get a path parameter from context, nil if not found
func GetParam(ctx context.Context, param string) *string {
	params := httptreemux.ContextParams(ctx)
	method, ok := params[param]
	if !ok {
		return nil
	}
	return &method
}

// GetQueryValue is a utility to get a parameter value from the query string, nil if not found
func GetQueryValue(r *http.Request, param string) *string {
	v := r.URL.Query().Get(param)
	if v == "" {
		return nil
	}
	return &v
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
