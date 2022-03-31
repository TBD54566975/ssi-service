// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	middleware "github.com/tbd54566975/vc-service/pkg/server/middleware"
	"log"
	"net/http"
	"os"
)

func API(shutdown chan os.Signal, log *log.Logger) *framework.Service {
	service := framework.NewService(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))

	readiness := Readiness{
		Log: log,
	}

	// generic service-level handlers
	service.Handle(http.MethodGet, "/health", health)
	service.Handle(http.MethodGet, "/readiness", readiness.handle)

	// v1 handlers
	v1Group := service.NewContextGroup("/v1")

	// DID handlers
	didGroup := v1Group.NewContextGroup("/dids")
	didGroup.GET("/", nil)
	didGroup.PUT("/:method", nil)
	didGroup.GET("/:method/:id", nil)

	return service
}
