package framework

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/dimfeld/httptreemux/v5"
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

// Convert stream to string.
func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.String()
}