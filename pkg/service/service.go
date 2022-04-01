package service

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/service/did"
	"github.com/tbd54566975/vc-service/pkg/service/framework"
	"github.com/tbd54566975/vc-service/pkg/storage"
	"log"
)

// VerifiableCredentialsService represents all services and their dependencies independent of transport
type VerifiableCredentialsService struct {
	services []framework.Service
}

// NewVerifiableCredentialsService creates a new instance of the VCS which instantiates all services and their
// dependencies independent of transport.
// TODO(gabe) make service loading config-based
func NewVerifiableCredentialsService(log *log.Logger) (*VerifiableCredentialsService, error) {
	services, err := instantiateServices(log)
	if err != nil {
		errMsg := "could not instantiate the verifiable credentials service"
		log.Printf(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	return &VerifiableCredentialsService{services: services}, nil
}

func (vcs *VerifiableCredentialsService) GetServices() []framework.Service {
	return vcs.services
}

// instantiateServices begins all instantiates and their dependencies
func instantiateServices(log *log.Logger) ([]framework.Service, error) {
	bolt, err := storage.NewBoltDB()
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate BoltDB")
	}
	didService, err := did.NewDIDService(log, []did.Method{did.KeyMethod}, bolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the DID service")
	}
	return []framework.Service{didService}, nil
}
