package middleware

import (
	"expvar"
	"runtime"

	"github.com/gin-gonic/gin"
)

// m contains global program counters
var m = struct {
	gr  *expvar.Int
	req *expvar.Int
	err *expvar.Int
}{
	gr:  expvar.NewInt("goroutines"),
	req: expvar.NewInt("requests"),
	err: expvar.NewInt("errors"),
}

func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// increment request counter
		m.req.Add(1)

		// update the counter for the # of active goroutines every 100 requests.
		// we may want to make the sampling rate a configurable value.
		if m.req.Value()%100 == 0 {
			m.gr.Set(int64(runtime.NumGoroutine()))
		}

		// if an error occurred, increment the errors counter
		if c.Errors != nil {
			m.err.Add(1)
		}
	}
}
