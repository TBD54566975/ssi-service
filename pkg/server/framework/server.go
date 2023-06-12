// Package framework is a minimal web framework.
package framework

import (
	"context"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/tbd54566975/ssi-service/config"
)

const (
	serviceName string = "ssi-service"
)

// Server is the entrypoint into our application and what configures our context object for each of our http router.
// Feel free to add any configuration data/logic on this Server struct.
type Server struct {
	*http.Server
	router      *gin.Engine
	tracer      trace.Tracer
	shutdown    chan os.Signal
	preShutdown []func(ctx context.Context) error
}

// RegisterPreShutdownHook registers a possibly blocking function to be run before Shutdown is called.
func (s *Server) RegisterPreShutdownHook(f func(_ context.Context) error) {
	s.preShutdown = append(s.preShutdown, f)
}

// PreShutdownHooks runs all hooks that were registered by calling RegisterPreShutdownHook.
func (s *Server) PreShutdownHooks(ctx context.Context) error {
	for _, f := range s.preShutdown {
		if err := f(ctx); err != nil {
			logrus.WithError(err).Warnf("pre shutdown hook error")
			return err
		}
	}
	return nil
}

// NewServer creates a Server that handles a set of routes for the application.
func NewServer(cfg config.ServerConfig, handler *gin.Engine, shutdown chan os.Signal) *Server {
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
		router:      handler,
		tracer:      tracer,
		shutdown:    shutdown,
		preShutdown: make([]func(ctx context.Context) error, 0),
	}
}
