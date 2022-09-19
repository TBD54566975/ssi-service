package service

import (
	"fmt"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
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
		errMsg := "could not instantiate SSI Service, invalid config"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}
	services, err := instantiateServices(config)
	if err != nil {
		errMsg := "could not instantiate the ssi service"
		return nil, util.LoggingErrorMsg(err, errMsg)
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
		errMsg := fmt.Sprintf("could not instantiate storage provider: %s", config.StorageProvider)
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	didService, err := did.NewDIDService(config.DIDConfig, storageProvider)
	if err != nil {
		errMsg := "could not instantiate the DID service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	schemaService, err := schema.NewSchemaService(config.SchemaConfig, storageProvider)
	if err != nil {
		errMsg := "could not instantiate the schema service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	credentialService, err := credential.NewCredentialService(config.CredentialConfig, storageProvider)
	if err != nil {
		errMsg := "could not instantiate the credential service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	manifestService, err := manifest.NewManifestService(config.ManifestConfig, storageProvider)
	if err != nil {
		errMsg := "could not instantiate the manifest service"
		return nil, util.LoggingErrorMsg(err, errMsg)
	}

	return []framework.Service{didService, schemaService, credentialService, manifestService}, nil
}
