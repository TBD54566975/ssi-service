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
	V1Prefix      = "/v1"
	DIDsPrefix    = "/dids"
	SchemasPrefix = "/schemas"
)

// SSIServer exposes all dependencies needed to run a http server and all its services
type SSIServer struct {
	*framework.Server
	*service.SSIService
	*service.Config
}

// NewSSIServer does two things: instantiates all service and registers their HTTP bindings
func NewSSIServer(shutdown chan os.Signal, config service.Config) (*SSIServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the SSIS
	logger := config.Logger
	middlewares := []framework.Middleware{middleware.Logger(logger), middleware.Errors(logger), middleware.Metrics(), middleware.Panics(logger)}
	httpServer := framework.NewHTTPServer(shutdown, middlewares...)
	ssi, err := service.InstantiateSSIService(config)
	if err != nil {
		return nil, err
	}

	// get all instantiated services
	services := ssi.GetServices()

	// service-level routers
	httpServer.Handle(http.MethodGet, "/health", router.Health)
	httpServer.Handle(http.MethodGet, "/readiness", router.Readiness(services, logger))

	// create the server instance to be returned
	server := SSIServer{
		Server:     httpServer,
		SSIService: ssi,
		Config:     &config,
	}

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

// SchemaAPI registers all HTTP router for the Schema Service
func (s *SSIServer) SchemaAPI(service svcframework.Service) error {
	schemaRouter, err := router.NewSchemaRouter(service, s.Logger)
	if err != nil {
		return errors.Wrap(err, "could not create Schema router")
	}

	handlerPath := V1Prefix + SchemasPrefix

	s.Handle(http.MethodGet, handlerPath, schemaRouter.GetAllSchemas)
	s.Handle(http.MethodPut, handlerPath, schemaRouter.CreateSchema)
	s.Handle(http.MethodGet, path.Join(handlerPath, "/:id"), schemaRouter.GetSchemaByID)
	return nil
}
