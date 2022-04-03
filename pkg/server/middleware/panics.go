package middleware

import (
	"context"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"log"
	"net/http"
	"runtime/debug"

	"github.com/pkg/errors"
)

// Panics recovers from panics and converts the panic into an error
func Panics(log *log.Logger) framework.Middleware {
	mw := func(handler framework.Handler) framework.Handler {
		wrapped := func(ctx context.Context, w http.ResponseWriter, r *http.Request) (err error) {

			v, ok := ctx.Value(framework.KeyRequestState).(*framework.RequestState)
			if !ok {
				return framework.NewShutdownError("request state missing from context.")
			}

			// defer a function to recover from a panic and set the err return
			// variable after the fact
			defer func() {
				if r := recover(); r != nil {
					// log the stack trace for this panic'd goroutine
					err = errors.Errorf("%s: \n%s", v.TraceID, debug.Stack())

					log.Printf("%s: PANIC :\n%s", v.TraceID, debug.Stack())
				}
			}()

			// Call the next handler and set its return value in the err variable.
			return handler(ctx, w, r)
		}

		return wrapped

	}

	return mw
}
