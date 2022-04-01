// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/vc-service/pkg/service/framework"

	"github.com/tbd54566975/vc-service/pkg/server/middleware"
	"github.com/tbd54566975/vc-service/pkg/server/router"
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

type VerifiableCredentialsHTTPServer struct {
	*framework.Server
	*service.VerifiableCredentialsService
	*log.Logger
}

// NewHTTPServer does two things: instantiates all service and registers their HTTP bindings
func NewHTTPServer(shutdown chan os.Signal, log *log.Logger) (*VerifiableCredentialsHTTPServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the VCS
	httpServer := framework.NewHTTPServer(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))
	vcs, err := service.NewVerifiableCredentialsService(log)
	if err != nil {
		return nil, err
	}
	services := vcs.GetServices()
	server := VerifiableCredentialsHTTPServer{
		Server:                       httpServer,
		VerifiableCredentialsService: vcs,
		Logger:                       log,
	}

	// service-level routers
	httpServer.Handle(http.MethodGet, "/health", router.Health)
	httpServer.Handle(http.MethodGet, "/readiness", router.Readiness(services, log))

	// start all services and their routers
	log.Printf("Starting [%d] services...\n", len(services))
	for _, s := range services {
		if err := server.instantiateRouter(s); err != nil {
			errMsg := fmt.Sprintf("unable to instaniate service: %s", s.Type())
			log.Fatalf(errMsg)
		}
		log.Printf("Service<%s> started successfully\n", s.Type())
	}

	return &server, nil
}

// instantiateRouter registers the HTTP router for a service with the HTTP server
// NOTE: all service API router must be registered here
func (server *VerifiableCredentialsHTTPServer) instantiateRouter(s svcframework.Service) error {
	serviceType := s.Type()
	switch serviceType {
	case svcframework.DID:
		return server.DecentralizedIdentityAPI(s)
	default:
		return fmt.Errorf("could not instantiate API for service: %s", serviceType)
	}
}

// DecentralizedIdentityAPI registers all HTTP router for the DID Service
func (server *VerifiableCredentialsHTTPServer) DecentralizedIdentityAPI(s svcframework.Service) error {
	didRouter, err := router.NewDIDRouter(s, server.Logger)
	if err != nil {
		return errors.Wrap(err, "could not create DID router")
	}

	handlerPath := V1Prefix + DIDsPrefix

	server.Handle(http.MethodGet, handlerPath, didRouter.GetDIDMethods)
	server.Handle(http.MethodPut, path.Join(handlerPath, "/:method"), didRouter.CreateDIDByMethod)
	server.Handle(http.MethodGet, path.Join(handlerPath, "/:method/:id"), didRouter.GetDIDByMethod)
	return nil
}
