package service

import (
	"github.com/pkg/errors"
	"github.com/tbd54566975/vc-service/pkg/service/did"
	"github.com/tbd54566975/vc-service/pkg/service/framework"
	"github.com/tbd54566975/vc-service/pkg/storage"
	"log"
)

// VerifiableCredentialsService is the total representation of this service, including transports and business logic
type VerifiableCredentialsService struct {
	services []framework.Service
}

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

// TODO(gabe) make this configurable
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
