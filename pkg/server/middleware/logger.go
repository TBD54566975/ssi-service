package middleware

import (
	"context"
	"github.com/tbd54566975/vc-service/pkg/server"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"log"
	"net/http"
	"time"
)

// Logger logs request info before and after a handler runs.
// logs to to stdout in the following format:
// Before:
// 		TraceID : (StatusCode) HTTPMethod Path -> IPAddr (latency)
// 		e.g. 12345 : (200) GET /users/1 -> 192.168.1.0 (4ms)
// After:
// 		TODO: add after format
// 		TODO: add after example
// TODO: make logging output configurable
func Logger(log *log.Logger) framework.Middleware {
	mw := func(handler server.Handler) server.Handler {

		wrapped := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			v, ok := ctx.Value(server.KeyRequestState).(*server.RequestState)
			if !ok {
				return framework.NewShutdownError("Request state missing from context")
			}

			log.Printf("%s : started : %s %s -> %s",
				v.TraceID,
				r.Method, r.URL.Path, r.RemoteAddr,
			)

			err := handler(ctx, w, r)

			log.Printf("%s : completed : %s %s -> %s (%d) (%s)",
				v.TraceID,
				r.Method, r.URL.Path, r.RemoteAddr,
				v.StatusCode, time.Since(v.Now),
			)

			return err
		}

		return wrapped
	}

	return mw
}
