// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"context"
	"fmt"
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

type API func(vcs *framework.Server, service service.Service) error

var (
	handlers = map[service.Type]API{
		service.DID: DecentralizedIdentityAPI,
	}
)

// StartHTTPServices is the entrypoint for all HTTP-based services
func StartHTTPServices(services []service.Service, shutdown chan os.Signal, log *log.Logger) *framework.Server {
	vcs := framework.NewHTTPServer(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))

	// service-level handlers
	vcs.Handle(http.MethodGet, "/health", health)
	vcs.Handle(http.MethodGet, "/readiness", NewReadinessService(vcs, log).Statuses)

	log.Printf("Starting [%d] HTTP handlers for services...\n", len(services))
	for _, s := range services {
		if err := vcs.RegisterService(s); err != nil {
			errMsg := fmt.Sprintf("unable to register service: %s", s.Type())
			log.Fatalf(errMsg)
		}
		log.Printf("Service<%s> HTTP handler started successfully\n", s.Type())
	}

	return vcs
}

func GetAPIHandlerForService(serviceType service.Type) (API, error) {
	api, ok := handlers[serviceType]
	if !ok {
		return nil, fmt.Errorf("could not get API handler for service: %s", serviceType)
	}
	return api, nil
}

// DecentralizedIdentityAPI registers all HTTP handlers for the DID Service
func DecentralizedIdentityAPI(vcs *framework.Server, s service.Service) error {
	// DID handlers
	if s.Type() != service.DID {
		return fmt.Errorf("cannot intantiate DID API with service type: %s", s.Type())
	}
	httpService := DIDServiceHTTP{DIDService: s.(service.DIDService)}
	handlerPath := V1Prefix + DIDsPrefix

	vcs.Handle(http.MethodGet, handlerPath, httpService.GetDIDMethods)
	vcs.Handle(http.MethodPut, path.Join(handlerPath, "/:method"), httpService.CreateDIDByMethod)
	vcs.Handle(http.MethodGet, path.Join(handlerPath, "/:method/:id"), httpService.GetDIDByMethod)
	return nil
}

// utility to get a path parameter from context, nil if not found
func getParam(ctx context.Context, param string) *string {
	params := httptreemux.ContextParams(ctx)
	method, ok := params[param]
	if !ok {
		return nil
	}
	return &method
}
