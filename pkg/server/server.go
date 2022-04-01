// Package framework is a minimal web framework.
package server

import (
	"context"
	"fmt"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/services"
	"net/http"
	"os"
	"syscall"
	"time"

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

// Server is the entrypoint into our application and what configures our context
// object for each of our http handlers. Feel free to add any configuration
// data/logic on this Server struct.
type Server struct {
	*httptreemux.ContextMux
	shutdown chan os.Signal
	mw       []framework.Middleware
	services []services.Service
}

// NewHTTPServer creates a Server that handles a set of routes for the application.
func NewHTTPServer(shutdown chan os.Signal, mw ...framework.Middleware) *Server {
	return &Server{
		ContextMux: httptreemux.NewContextMux(),
		shutdown:   shutdown,
		mw:         mw,
	}
}

// RegisterService associates a service with the service and registers its HTTP handler
func (vcs *Server) RegisterService(s services.Service) error {
	if vcs == nil {
		return errors.New("cannot register service on empty vcs")
	}
	if len(vcs.services) == 0 {
		vcs.services = []services.Service{s}
	} else {
		vcs.services = append(vcs.services, s)
	}

	if err := vcs.InstantiateAPI(s); err != nil {
		errMsg := fmt.Sprintf("unable to start service: %s", s.Type())
		return errors.New(errMsg)
	}
	return nil
}

func (vcs *Server) GetServices() []services.Service {
	return vcs.services
}

// InstantiateAPI registers HTTP handlers for each service
func (vcs *Server) InstantiateAPI(s services.Service) error {
	handler, err := GetAPIHandlerForService(s.Type())
	if err != nil {
		return err
	}
	return handler(vcs, s)
}

// Handle sets a handler function for a given HTTP method and path pair
// to the server mux.
func (vcs *Server) Handle(method string, path string, handler Handler, mw ...framework.Middleware) {
	// first wrap route specific middleware
	handler = framework.WrapMiddleware(mw, handler)

	// then wrap app specific middleware
	handler = framework.WrapMiddleware(vcs.mw, handler)

	// request handler function
	h := func(w http.ResponseWriter, r *http.Request) {
		requestState := RequestState{
			TraceID: uuid.New().String(),
			Now:     time.Now(),
		}

		ctx := context.WithValue(r.Context(), KeyRequestState, &requestState)

		// onion the request through all the registered middleware
		if err := handler(ctx, w, r); err != nil {
			vcs.SignalShutdown()
			return
		}
	}

	vcs.ContextMux.Handle(method, path, h)
}

// SignalShutdown is used to gracefully shut down the server when an integrity
// issue is identified.
func (vcs *Server) SignalShutdown() {
	vcs.shutdown <- syscall.SIGTERM
}
