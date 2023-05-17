// Package framework is a minimal web framework.
package framework

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/uuid"

	"github.com/tbd54566975/ssi-service/config"
)

type contextKey string

const (
	KeyRequestState    contextKey = "keyRequestState"
	ShutdownErrorState contextKey = "shutdownError"

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
func NewHTTPServer(config config.ServerConfig, shutdown chan os.Signal, mws gin.HandlersChain) *Server {
	var tracer trace.Tracer
	if config.JagerEnabled {
		tracer = otel.Tracer(serviceName)
	}
	router := gin.Default()
	router.Use(mws...)

	return &Server{
		Server: &http.Server{
			Addr:              config.APIHost,
			Handler:           router,
			ReadTimeout:       config.ReadTimeout,
			ReadHeaderTimeout: config.ReadTimeout,
			WriteTimeout:      config.WriteTimeout,
		},
		router:   router,
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
		requestState := RequestState{
			TraceID: uuid.New().String(),
			Now:     time.Now(),
		}
		r := c.Request
		ctx := context.WithValue(r.Context(), KeyRequestState, &requestState)

		// init a span, but only if the tracer is initialized
		if s.tracer != nil {
			_, span := s.tracer.Start(ctx, path)
			defer span.End()
			body, err := PeekRequestBody(r)
			if err != nil {
				// log the error and continue the trace with an empty body value
				logrus.Errorf("failed to read request body during tracing: %v", err)
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
			logrus.Errorf("request failed: %q", err)
			s.SignalShutdown()
			return
		}
	}

	// add the handler to the router
	s.router.Handle(method, path, h)
}

// SignalShutdown is used to gracefully shut down the server when an integrity
// issue is identified.
func (s *Server) SignalShutdown() {
	s.shutdown <- syscall.SIGTERM
}
