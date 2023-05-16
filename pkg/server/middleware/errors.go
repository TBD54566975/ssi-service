package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"

	"go.opentelemetry.io/otel/trace"
)

// Errors handles errors coming out of the call stack. It detects safe application
// errors (aka SafeError) that are used to respond to the requester in a
// normalized way. Unexpected errors (status >= 500) are logged.
func Errors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		ctx := c.Request.Context()
		tracer := trace.SpanFromContext(ctx).TracerProvider().Tracer(config.ServiceName)
		ctx, span := tracer.Start(ctx, "service.middleware.errors")
		defer span.End()

		v, ok := c.Value(framework.KeyRequestState).(*framework.RequestState)
		if !ok {
			c.Set(framework.ShutdownErrorState, framework.NewShutdownError("request state missing from context."))
			return
		}

		errors := c.Errors.ByType(gin.ErrorTypeAny)
		if len(errors) > 0 {
			// check if there's a shutdown-worthy error
			for _, e := range errors {
				if framework.IsShutdown(e.Err) {
					c.Set(framework.ShutdownErrorState, e.Err)
					return
				}
			}

			// otherwise just log the errors and return
			logrus.Printf("%s : ERROR : %v", v.TraceID, errors)
			c.JSON(-1, errors)
		}
	}
}
