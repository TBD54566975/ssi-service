package middleware

import (
	"context"
	"expvar"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"net/http"
	"runtime"
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

func Metrics() framework.Middleware {
	mw := func(handler framework.Handler) framework.Handler {
		wrapped := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			err := handler(ctx, w, r)

			// increment request counter
			m.req.Add(1)

			// update the counter for the # of active goroutines every 100 requests.
			//! we may want to make the sampling rate a configurable value.
			if m.req.Value()%100 == 0 {
				m.gr.Set(int64(runtime.NumGoroutine()))
			}

			// if an error occurred, increment the errors counter
			if err != nil {
				m.err.Add(1)
			}

			return err
		}

		return wrapped
	}

	return mw
}
