package service

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// SSIService represents all services and their dependencies independent of transport
type SSIService struct {
	services []framework.Service
	config   config.ServicesConfig
}

// InstantiateSSIService creates a new instance of the SSIS which instantiates all services and their
// dependencies independent of transport.
func InstantiateSSIService(config config.ServicesConfig) (*SSIService, error) {
	if err := validateServiceConfig(config); err != nil {
		err := errors.Wrapf(err, "could not instantiate SSI Service, invalid config")
		logrus.WithError(err).Error()
		return nil, err
	}
	services, err := instantiateServices(config)
	if err != nil {
		err := errors.Wrapf(err, "could not instantiate the verifiable credentials service")
		logrus.WithError(err).Error()
		return nil, err
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
func instantiateServices(config config.ServicesConfig) ([]framework.Service, error) {
	storageProvider, err := storage.NewStorage(storage.Storage(config.StorageProvider))
	if err != nil {
		return nil, errors.Wrapf(err, "could not instantiate storage provider: %s", config.StorageProvider)
	}

	didService, err := did.NewDIDService(config.DIDConfig, storageProvider)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the DID service")
	}

	schemaService, err := schema.NewSchemaService(config.SchemaConfig, storageProvider)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate the schema service")
	}
	return []framework.Service{didService, schemaService}, nil
}
