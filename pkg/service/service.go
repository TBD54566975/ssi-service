package service

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
)

// SSIService represents all services and their dependencies independent of transport
type SSIService struct {
	*log.Logger
	services []framework.Service
	config   config.ServicesConfig
}

// InstantiateSSIService creates a new instance of the SSIS which instantiates all services and their
// dependencies independent of transport.
func InstantiateSSIService(logger *log.Logger, config config.ServicesConfig) (*SSIService, error) {
	if logger == nil {
		return nil, errors.New("logger not initialized")
	}
	if err := validateServiceConfig(config); err != nil {
		errMsg := fmt.Sprintf("could not instantiate SSI Service, invalid config: %s", err.Error())
		log.Printf(errMsg)
		return nil, errors.New(errMsg)
	}
	services, err := instantiateServices(logger, config)
	if err != nil {
		errMsg := fmt.Sprintf("could not instantiate the verifiable credentials service: %s", err.Error())
		log.Printf(errMsg)
		return nil, errors.New(errMsg)
	}
	return &SSIService{services: services}, nil
}

func validateServiceConfig(config config.ServicesConfig) error {
	if !storage.IsStorageAvailable(config.StorageProvider) {
		return fmt.Errorf("%s storage provider configured, but not available", config.StorageProvider)
	}
	if config.DIDConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.DID)
	}
	if config.SchemaConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Schema)
	}
	return nil
}

// GetServices returns the instantiated service providers
func (ssi *SSIService) GetServices() []framework.Service {
	return ssi.services
}

// instantiateServices begins all instantiates and their dependencies
func instantiateServices(logger *log.Logger, config config.ServicesConfig) ([]framework.Service, error) {
	storageProvider, err := storage.NewStorage(storage.Storage(config.StorageProvider), logger)
	if err != nil {
		return nil, errors.Wrapf(err, "could not instantiate storage provider: %s", config.StorageProvider)
	}

	didService, err := did.NewDIDService(logger, config.DIDConfig, storageProvider)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the DID service")
	}

	schemaService, err := schema.NewSchemaService(logger, config.SchemaConfig, storageProvider)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the schema service")
	}
	return []framework.Service{didService, schemaService}, nil
}
