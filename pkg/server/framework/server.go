// Package framework is a minimal web framework.
package framework

import (
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/tbd54566975/ssi-service/config"
)

type contextKey string

const (
	TraceIDKey       contextKey = "traceID"
	ShutdownErrorKey contextKey = "shutdownError"

	serviceName string = "ssi-service"
)

func (c contextKey) String() string {
	return string(c)
}

type RequestState struct {
	TraceID    string
	Now        time.Time
	StatusCode int
}

// Server is the entrypoint into our application and what configures our context object for each of our http router.
// Feel free to add any configuration data/logic on this Server struct.
type Server struct {
	*http.Server
	router   *gin.Engine
	tracer   trace.Tracer
	shutdown chan os.Signal
}

type Handler func(c *gin.Context) error

// NewHTTPServer creates a Server that handles a set of routes for the application.
func NewHTTPServer(cfg config.ServerConfig, handler *gin.Engine, shutdown chan os.Signal) *Server {
	var tracer trace.Tracer
	if cfg.JagerEnabled {
		tracer = otel.Tracer(serviceName)
	}

	return &Server{
		Server: &http.Server{
			Addr:              cfg.APIHost,
			Handler:           handler,
			ReadTimeout:       cfg.ReadTimeout,
			ReadHeaderTimeout: cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
		},
		router:   handler,
		tracer:   tracer,
		shutdown: shutdown,
	}
}

// Handle sets a handler function for a given HTTP method and path pair
// to the server mux.
func (s *Server) Handle(method string, path string, handler Handler, middleware ...gin.HandlerFunc) {
	// add the middleware to the router
	s.router.Use(middleware...)

	// request handler function
	h := func(c *gin.Context) {
		r := c.Request

		// init a span, but only if the tracer is initialized
		if s.tracer != nil {
			_, span := s.tracer.Start(c, path)
			traceID := span.SpanContext().TraceID().String()
			c.Set(TraceIDKey.String(), traceID)

			defer span.End()
			body, err := PeekRequestBody(r)
			if err != nil {
				// log the error and continue the trace with an empty body value
				logrus.WithError(err).Error("failed to read request body during tracing")
			}
			span.SetAttributes(
				attribute.String("method", method),
				attribute.String("path", path),
				attribute.String("host", r.Host),
				attribute.String("user-agent", r.UserAgent()),
				attribute.String("proto", r.Proto),
				attribute.String("body", body),
			)
		}

		// handle the request
		if err := handler(c); err != nil {
			// if there's still an error at this point (not extracted by our errors middleware)
			// we know it's an unsafe error and worth shutting down over
			logrus.WithError(err).Errorf("request failed")
			if IsShutdown(err) {
				logrus.WithError(err).Errorf("unsafe error, shutting down")
				s.SignalShutdown()
			}
			return
		}
	}

	// add the handler to the router
	s.router.Handle(method, path, h)
}

// SignalShutdown is used to gracefully shut down the server when an integrity issue is identified.
func (s *Server) SignalShutdown() {
	s.shutdown <- syscall.SIGTERM
}
