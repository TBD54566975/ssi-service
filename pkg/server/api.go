// Package server contains the full set of handler functions and routes
// supported by the http api
package server

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/internal/did"
	"github.com/tbd54566975/vc-service/pkg/server/api"
	"github.com/tbd54566975/vc-service/pkg/server/middleware"
	"github.com/tbd54566975/vc-service/pkg/services"
	didsvc "github.com/tbd54566975/vc-service/pkg/services/did"
	"github.com/tbd54566975/vc-service/pkg/storage"
	"log"
	"net/http"
	"os"
	"path"
)

const (
	V1Prefix   = "/v1"
	DIDsPrefix = "/dids"
)

type API func(vcs *Server, service services.Service) error

var (
	handlers = map[services.Type]API{
		services.DID: DecentralizedIdentityAPI,
	}
)

// TODO(gabe) make this configurable
// instantiateServices begins all instantiates and their dependencies
func instantiateServices() ([]services.Service, error) {
	bolt, err := storage.NewBoltDB()
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate BoltDB")
	}
	boltDIDStorage, err := did.NewBoltDIDStorage(bolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate BoltDB DID storage")
	}
	didService, err := didsvc.NewDIDService([]didsvc.Method{didsvc.KeyMethod}, boltDIDStorage)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the DID service")
	}
	return []services.Service{didService}, nil
}

// StartServices does two things: instantiates all services and registers their HTTP bindings
func StartServices(shutdown chan os.Signal, log *log.Logger) (*Server, error) {
	services, err := instantiateServices()
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate services")
	}
	vcs := NewHTTPServer(shutdown, middleware.Logger(log), middleware.Errors(log), middleware.Metrics(), middleware.Panics(log))

	// service-level handlers
	vcs.Handle(http.MethodGet, "/health", api.Health)
	vcs.Handle(http.MethodGet, "/readiness", api.NewReadinessService(vcs, log).Statuses)

	log.Printf("Starting [%d] HTTP handlers for services...\n", len(services))
	for _, s := range services {
		if err := vcs.RegisterService(s); err != nil {
			errMsg := fmt.Sprintf("unable to register service: %s", s.Type())
			log.Fatalf(errMsg)
		}
		log.Printf("Service<%s> HTTP handler started successfully\n", s.Type())
	}

	return vcs, nil
}

func GetAPIHandlerForService(serviceType services.Type) (API, error) {
	handler, ok := handlers[serviceType]
	if !ok {
		return nil, fmt.Errorf("could not get API handler for service: %s", serviceType)
	}
	return handler, nil
}

// DecentralizedIdentityAPI registers all HTTP handlers for the DID Service
func DecentralizedIdentityAPI(vcs *Server, s services.Service) error {
	// DID handlers
	if s.Type() != services.DID {
		return fmt.Errorf("cannot intantiate DID API with service type: %s", s.Type())
	}
	httpService := api.DIDServiceHTTP{Service: s.(didsvc.Service)}
	handlerPath := V1Prefix + DIDsPrefix

	vcs.Handle(http.MethodGet, handlerPath, httpService.GetDIDMethods)
	vcs.Handle(http.MethodPut, path.Join(handlerPath, "/:method"), httpService.CreateDIDByMethod)
	vcs.Handle(http.MethodGet, path.Join(handlerPath, "/:method/:id"), httpService.GetDIDByMethod)
	return nil
}
