// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"context"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	middleware "github.com/tbd54566975/vc-service/pkg/server/middleware"
	"github.com/tbd54566975/vc-service/pkg/service"
	"log"
	"net/http"
	"os"
	"path"
)

const (
	V1Prefix   = "/v1"
	DIDsPrefix = "/dids"
)

type Services struct {
	service.DIDService
}

func API(services Services, shutdown chan os.Signal, log *log.Logger) *framework.Service {
	vcs := framework.NewService(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))

	readiness := Readiness{
		Log: log,
	}

	// generic vcs-level handlers
	vcs.Handle(http.MethodGet, "/health", health)
	vcs.Handle(http.MethodGet, "/readiness", readiness.handle)

	// v1 handlers

	// DID handlers
	vcs.Handle(http.MethodGet, path.Join(V1Prefix, DIDsPrefix), GetDIDMethods)
	vcs.Handle(http.MethodPut, path.Join(V1Prefix, DIDsPrefix, "/:method"), CreateDIDByMethod)
	vcs.Handle(http.MethodGet, path.Join(V1Prefix, DIDsPrefix, "/:method/:id"), GetDIDByMethod)

	return vcs
}

// utility to get a path parameter from context, nil if not found
func getParam(ctx context.Context, param string) *string {
	params := httptreemux.ContextParams(ctx)
	method, ok := params[MethodParam]
	if !ok {
		return nil
	}
	return &method
}
