package framework

import (
	"github.com/gin-gonic/gin"
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
