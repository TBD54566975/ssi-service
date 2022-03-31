// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	middleware "github.com/tbd54566975/vc-service/pkg/server/middleware"
	"log"
	"net/http"
	"os"
	"path"
)

const (
	V1Prefix   = "/v1"
	DIDsPrefix = "/dids"
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

	// DID handlers
	service.Handle(http.MethodGet, path.Join(V1Prefix, DIDsPrefix), GetDIDMethods)
	service.Handle(http.MethodPut, path.Join(V1Prefix, DIDsPrefix, "/:method"), CreateDIDByMethod)
	service.Handle(http.MethodGet, path.Join(V1Prefix, DIDsPrefix, "/:method/:id"), GetDIDByMethod)

	return service
}
