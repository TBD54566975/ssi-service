// Package framework is a minimal web framework.
package framework

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/dimfeld/httptreemux/v5"
	"github.com/google/uuid"
)

type ctxKey int

const KeyRequestState ctxKey = 1

type RequestState struct {
	TraceID    string
	Now        time.Time
	StatusCode int
}

// A Handler is a type that handles a http request within our own little mini
// framework.
type Handler func(ctx context.Context, w http.ResponseWriter, r *http.Request) error

// Service is the entrypoint into our application and what configures our context
// object for each of our http handlers. Feel free to add any configuration
// data/logic on this Service struct.
type Service struct {
	*httptreemux.ContextMux
	shutdown chan os.Signal
	mw       []Middleware
}

// NewService creates a Service that handles a set of routes for the application.
func NewService(shutdown chan os.Signal, mw ...Middleware) *Service {
	service := Service{
		ContextMux: httptreemux.NewContextMux(),
		shutdown:   shutdown,
		mw:         mw,
	}

	return &service
}

// Handle sets a handler function for a given HTTP method and path pair
// to the service server mux.
func (service *Service) Handle(method string, path string, handler Handler, mw ...Middleware) {
	// first wrap route specific middleware
	handler = wrapMiddleware(mw, handler)

	// then wrap app specific middleware
	handler = wrapMiddleware(service.mw, handler)

	// request handler function
	h := func(w http.ResponseWriter, r *http.Request) {
		requestState := RequestState{
			TraceID: uuid.New().String(),
			Now:     time.Now(),
		}

		ctx := context.WithValue(r.Context(), KeyRequestState, &requestState)

		// onion the request through all of the registered middleware
		if err := handler(ctx, w, r); err != nil {
			service.SignalShutdown()
			return
		}
	}

	service.ContextMux.Handle(method, path, h)
}

// SignalShutdown is used to gracefully shut down the service when an integrity
// issue is identified.
func (service *Service) SignalShutdown() {
	service.shutdown <- syscall.SIGTERM
}
