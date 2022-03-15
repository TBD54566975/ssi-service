// Package handlers contains the full set of handler functions and routes
// supported by the http api
package handlers

import (
	"log"
	"net/http"
	"os"

	"github.com/tbd54566975/vc-service/framework"
	"github.com/tbd54566975/vc-service/middleware"
)

func API(build string, shutdown chan os.Signal, log *log.Logger) *framework.Service {
	service := framework.NewService(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))

	readiness := readiness{
		log: log,
	}

	// attach all handlers here
	service.Handle(http.MethodGet, "/health", health)
	service.Handle(http.MethodGet, "/readiness", readiness.handle)

	return service
}
