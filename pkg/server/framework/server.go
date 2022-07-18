// Package framework is a minimal web framework.
package framework

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/dimfeld/httptreemux/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/google/uuid"
)

type ctxKey int

const KeyRequestState ctxKey = 1
var tracer = otel.Tracer("SSI SERVICE")

type RequestState struct {
	TraceID    string
	Now        time.Time
	StatusCode int
}

// A Handler is a type that handles a http request within our own little mini
// framework.
type Handler func(ctx context.Context, w http.ResponseWriter, r *http.Request) error

// Server is the entrypoint into our application and what configures our context
// object for each of our http router. Feel free to add any configuration
// data/logic on this Server struct.
type Server struct {
	*httptreemux.ContextMux
	shutdown chan os.Signal
	mw       []Middleware
}

// NewHTTPServer creates a Server that handles a set of routes for the application.
func NewHTTPServer(shutdown chan os.Signal, mw ...Middleware) *Server {
	return &Server{
		ContextMux: httptreemux.NewContextMux(),
		shutdown:   shutdown,
		mw:         mw,
	}
}

// Handle sets a handler function for a given HTTP method and path pair
// to the server mux.
func (s *Server) Handle(method string, path string, handler Handler, mw ...Middleware) {
	// first wrap route specific middleware
	handler = WrapMiddleware(mw, handler)

	// then wrap app specific middleware
	handler = WrapMiddleware(s.mw, handler)

	// request handler function
	h := func(w http.ResponseWriter, r *http.Request) {
		requestState := RequestState{
			TraceID: uuid.New().String(),
			Now:     time.Now(),
		}
		ctx := context.WithValue(r.Context(), KeyRequestState, &requestState)

		// init a span
		ctx, span := tracer.Start(ctx, path)
		span.SetAttributes(
			attribute.String("method", method),
			attribute.String("path", path),
			attribute.String("host", r.Host),
			attribute.String("prot", r.Proto),
			attribute.String("body", StreamToString(r.Body)),
		)

		defer span.End()

		// onion the request through all the registered middleware
		if err := handler(ctx, w, r); err != nil {
			s.SignalShutdown()
			return
		}
	}

	s.ContextMux.Handle(method, path, h)
}

// SignalShutdown is used to gracefully shut down the server when an integrity
// issue is identified.
func (s *Server) SignalShutdown() {
	s.shutdown <- syscall.SIGTERM
}
