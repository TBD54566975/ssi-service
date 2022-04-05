// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"

	"github.com/tbd54566975/ssi-service/pkg/server/middleware"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service"
	"log"
	"net/http"
	"os"
	"path"
)

const (
	V1Prefix   = "/v1"
	DIDsPrefix = "/dids"
)

type SSIServer struct {
	*framework.Server
	*service.SSIService
	*log.Logger
}

// NewSSIServer does two things: instantiates all service and registers their HTTP bindings
func NewSSIServer(shutdown chan os.Signal, config service.Config) (*SSIServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the SSIS
	logger := config.Logger
	httpServer := framework.NewHTTPServer(shutdown, middleware.Logger(logger), middleware.Errors(logger), middleware.Metrics(), middleware.Panics(logger))
	ssi, err := service.NewSSIService(config)
	if err != nil {
		return nil, err
	}
	services := ssi.GetServices()
	server := SSIServer{
		Server:     httpServer,
		SSIService: ssi,
		Logger:     logger,
	}

	// service-level routers
	httpServer.Handle(http.MethodGet, "/health", router.Health)
	httpServer.Handle(http.MethodGet, "/readiness", router.Readiness(services, logger))

	// start all services and their routers
	log.Printf("Starting [%d] services...\n", len(services))
	for _, s := range services {
		if err := server.instantiateRouter(s); err != nil {
			errMsg := fmt.Sprintf("unable to instaniate service<%s>: %s", s.Type(), err.Error())
			log.Fatalf(errMsg)
		}
		log.Printf("Service<%s> started successfully\n", s.Type())
	}

	return &server, nil
}

// instantiateRouter registers the HTTP router for a service with the HTTP server
// NOTE: all service API router must be registered here
func (s *SSIServer) instantiateRouter(service svcframework.Service) error {
	serviceType := service.Type()
	switch serviceType {
	case svcframework.DID:
		return s.DecentralizedIdentityAPI(service)
	default:
		return fmt.Errorf("could not instantiate API for service: %s", serviceType)
	}
}

// DecentralizedIdentityAPI registers all HTTP router for the DID Service
func (s *SSIServer) DecentralizedIdentityAPI(service svcframework.Service) error {
	didRouter, err := router.NewDIDRouter(service, s.Logger)
	if err != nil {
		return errors.Wrap(err, "could not create DID router")
	}

	handlerPath := V1Prefix + DIDsPrefix

	s.Handle(http.MethodGet, handlerPath, didRouter.GetDIDMethods)
	s.Handle(http.MethodPut, path.Join(handlerPath, "/:method"), didRouter.CreateDIDByMethod)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:method/:id"), didRouter.GetDIDByMethod)
	return nil
}
