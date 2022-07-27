package framework

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
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
func PeekRequestBody(body io.ReadCloser) (string, error) {
	var buf bytes.Buffer
	tee := io.TeeReader(body, &buf)
	bodyBytes, err := ioutil.ReadAll(tee)
	if err != nil {
		return "", errors.Wrap(err, "could not ready request body")
	}
	return string(bodyBytes), nil
}

func peekBuffer(buf *bytes.Buffer, b []byte) (int, error) {
	copiedBuffer := bytes.NewBuffer(buf.Bytes())
	return copiedBuffer.Read(b)
}
