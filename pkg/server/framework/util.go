package framework

import (
	"context"
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
