// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"fmt"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/server/middleware"
	"github.com/tbd54566975/vc-service/pkg/service"
	"github.com/tbd54566975/vc-service/pkg/service/did"
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
}

// StartHTTPServer does two things: instantiates all service and registers their HTTP bindings
func StartHTTPServer(services []service.Service, shutdown chan os.Signal, log *log.Logger) (*VerifiableCredentialsHTTPServer, error) {
	// creates an HTTP server from the framework, and wrap it to extend it for the VCS
	httpServer := framework.NewHTTPServer(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))
	vcsHTTP := VerifiableCredentialsHTTPServer{Server: httpServer}

	// service-level handlers
	httpServer.Handle(http.MethodGet, "/health", health)
	httpServer.Handle(http.MethodGet, "/readiness", readinessService(servicesToGet{services: services}, log).ready)

	log.Printf("Starting [%d] HTTP handlers for service...\n", len(services))
	for _, s := range services {
		if err := vcsHTTP.instantiateAPI(s); err != nil {
			errMsg := fmt.Sprintf("unable to instaniate API for service: %s", s.Type())
			log.Fatalf(errMsg)
		}
		log.Printf("Service<%s> HTTP handler started successfully\n", s.Type())
	}

	return &vcsHTTP, nil
}

// instantiateAPI registers the HTTP handlers for a service with the HTTP server
func (server *VerifiableCredentialsHTTPServer) instantiateAPI(s service.Service) error {
	serviceType := s.Type()
	switch serviceType {
	case service.DID:
		return server.DecentralizedIdentityAPI(s)
	default:
		return fmt.Errorf("could not instantiate API for service: %s", serviceType)
	}
}

// DecentralizedIdentityAPI registers all HTTP handlers for the DID Service
func (server *VerifiableCredentialsHTTPServer) DecentralizedIdentityAPI(s service.Service) error {
	// DID handlers
	if s.Type() != service.DID {
		return fmt.Errorf("cannot intantiate DID API with service type: %s", s.Type())
	}
	httpService := DIDServiceHTTP{Service: s.(did.Service)}
	handlerPath := V1Prefix + DIDsPrefix

	server.Handle(http.MethodGet, handlerPath, httpService.GetDIDMethods)
	server.Handle(http.MethodPut, path.Join(handlerPath, "/:method"), httpService.CreateDIDByMethod)
	server.Handle(http.MethodGet, path.Join(handlerPath, "/:method/:id"), httpService.GetDIDByMethod)
	return nil
}
