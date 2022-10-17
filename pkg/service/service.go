package service

import (
	"fmt"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/dwn"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
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
	if config.KeyStoreConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.KeyStore)
	}
	if config.DIDConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.DID)
	}
	if config.SchemaConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Schema)
	}
	if config.CredentialConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Credential)
	}
	if config.ManifestConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Manifest)
	}
	if config.DWNConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.DWN)
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

	keyStoreService, err := keystore.NewKeyStoreService(config.KeyStoreConfig, storageProvider)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate keystore service")
	}

	didService, err := did.NewDIDService(config.DIDConfig, storageProvider, keyStoreService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the DID service")
	}
	didResolver := didService.GetResolver()

	schemaService, err := schema.NewSchemaService(config.SchemaConfig, storageProvider, keyStoreService, didResolver)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the schema service")
	}

	credentialService, err := credential.NewCredentialService(config.CredentialConfig, storageProvider, keyStoreService, didResolver, schemaService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the credential service")
	}

	manifestService, err := manifest.NewManifestService(config.ManifestConfig, storageProvider, keyStoreService, didResolver, credentialService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the manifest service")
	}

	dwnService, err := dwn.NewDWNService(config.DWNConfig, storageProvider, keyStoreService, manifestService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the dwn service")
	}

	return []framework.Service{keyStoreService, didService, schemaService, credentialService, manifestService, dwnService}, nil
}
