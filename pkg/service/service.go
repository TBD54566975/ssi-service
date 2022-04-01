package service

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/server"
	"github.com/tbd54566975/vc-service/pkg/service/did"
	"github.com/tbd54566975/vc-service/pkg/storage"
	"log"
	"os"
)

type (
	Type        string
	StatusState string
)

const (
	// List of all service

	DID Type = "did-service"

	StatusReady    StatusState = "ready"
	StatusNotReady StatusState = "not ready"
)

// Status is for service reporting on their status
type Status struct {
	Status  StatusState
	Message string
}

// Service is an interface each service must comply with to be registered and orchestrated by the http.
type Service interface {
	Type() Type
	Status() Status
}

// VerifiableCredentialsService is the total representation of this service, including transports and business logic
type VerifiableCredentialsService struct {
	*server.VerifiableCredentialsHTTPServer
	services []Service
}

func NewVerifiableCredentialsService(shutdown chan os.Signal, log *log.Logger) (*VerifiableCredentialsService, error) {
	services, err := instantiateServices()
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate service")
	}

	httpServer, err := server.StartHTTPServer(services, shutdown, log)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate http http")
	}

	return &VerifiableCredentialsService{
		VerifiableCredentialsHTTPServer: httpServer,
		services:                        services,
	}, nil
}

func (vcs *VerifiableCredentialsService) getServices() []Service {
	return vcs.services
}

// TODO(gabe) make this configurable
// instantiateServices begins all instantiates and their dependencies
func instantiateServices() ([]Service, error) {
	bolt, err := storage.NewBoltDB()
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate BoltDB")
	}
	didService, err := did.NewDIDService([]did.Method{did.KeyMethod}, bolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the DID service")
	}
	return []Service{didService}, nil
}
