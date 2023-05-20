// Package framework is a minimal web framework.
package framework

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/tbd54566975/ssi-service/config"
)

type contextKey string

const (
	TraceIDKey contextKey = "traceID"

	serviceName string = "ssi-service"
)

func (c contextKey) String() string {
	return string(c)
}

// Server is the entrypoint into our application and what configures our context object for each of our http router.
// Feel free to add any configuration data/logic on this Server struct.
type Server struct {
	*http.Server
	router   *gin.Engine
	tracer   trace.Tracer
	shutdown chan os.Signal
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
		router:   handler,
		tracer:   tracer,
		shutdown: shutdown,
	}
}
