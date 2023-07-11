package service

import (
	"fmt"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuance"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
	wellknown "github.com/tbd54566975/ssi-service/pkg/service/well-known"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// SSIService represents all services and their dependencies independent of transport
type SSIService struct {
	KeyStore         *keystore.Service
	DID              *did.Service
	Schema           *schema.Service
	Issuance         *issuance.Service
	Credential       *credential.Service
	Manifest         *manifest.Service
	Presentation     *presentation.Service
	Operation        *operation.Service
	Webhook          *webhook.Service
	storage          storage.ServiceStorage
	BatchDID         *did.BatchService
	DIDConfiguration *wellknown.DIDConfigurationService
}

// InstantiateSSIService creates a new instance of the SSIS which instantiates all services and their
// dependencies independent of transport.
func InstantiateSSIService(config config.ServicesConfig) (*SSIService, error) {
	if err := validateServiceConfig(config); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate SSI Service, invalid config")
	}
	service, err := instantiateServices(config)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not instantiate the ssi service")
	}
	return service, nil
}

func validateServiceConfig(config config.ServicesConfig) error {
	if !storage.IsStorageAvailable(storage.Type(config.StorageProvider)) {
		return fmt.Errorf("%s storage provider configured, but not available", config.StorageProvider)
	}
	if config.KeyStoreConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.KeyStore)
	}
	if config.DIDConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.DID)
	}
	if config.IssuanceServiceConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Issuance)
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
	if config.PresentationConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Presentation)
	}
	if config.WebhookConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Webhook)
	}
	return nil
}

// instantiateServices begins all instantiates and their dependencies
func instantiateServices(config config.ServicesConfig) (*SSIService, error) {
	storageProvider, err := storage.NewStorage(storage.Type(config.StorageProvider), config.StorageOptions...)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsgf(err, "could not instantiate storage provider: %s", config.StorageProvider)
	}

	webhookService, err := webhook.NewWebhookService(config.WebhookConfig, storageProvider)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the webhook service")
	}

	if err := keystore.EnsureServiceKeyExists(config.KeyStoreConfig, storageProvider); err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not ensure the service key exists")
	}
	keyStoreServiceFactory := keystore.NewKeyStoreServiceFactory(config.KeyStoreConfig, storageProvider)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the keystore service factory")
	}

	keyStoreService, err := keyStoreServiceFactory(storageProvider)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate KeyStore service")
	}

	batchDIDService, err := did.NewBatchDIDService(config.DIDConfig, storageProvider, keyStoreServiceFactory)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate batch DID service")
	}

	didService, err := did.NewDIDService(config.DIDConfig, storageProvider, keyStoreService)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the DID service")
	}
	didResolver := didService.GetResolver()

	schemaService, err := schema.NewSchemaService(config.SchemaConfig, storageProvider, keyStoreService, didResolver)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the schema service")
	}

	issuanceService, err := issuance.NewIssuanceService(config.IssuanceServiceConfig, storageProvider)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the issuance service")
	}

	credentialService, err := credential.NewCredentialService(config.CredentialConfig, storageProvider, keyStoreService, didResolver, schemaService)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the credential service")
	}

	presentationService, err := presentation.NewPresentationService(config.PresentationConfig, storageProvider, didResolver, schemaService, keyStoreService)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the presentation service")
	}

	manifestService, err := manifest.NewManifestService(config.ManifestConfig, storageProvider, keyStoreService, didResolver, credentialService, presentationService)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the manifest service")
	}

	operationService, err := operation.NewOperationService(storageProvider)
	if err != nil {
		return nil, sdkutil.LoggingErrorMsg(err, "could not instantiate the operation service")
	}

	didConfigurationService := wellknown.NewDIDConfigurationService(keyStoreService)
	return &SSIService{
		KeyStore:         keyStoreService,
		DID:              didService,
		BatchDID:         batchDIDService,
		Schema:           schemaService,
		Issuance:         issuanceService,
		Credential:       credentialService,
		Manifest:         manifestService,
		Presentation:     presentationService,
		Operation:        operationService,
		Webhook:          webhookService,
		DIDConfiguration: didConfigurationService,
		storage:          storageProvider,
	}, nil
}

// GetServices returns all services
func (s *SSIService) GetServices() []framework.Service {
	return []framework.Service{
		s.KeyStore,
		s.DID,
		s.Schema,
		s.Issuance,
		s.Credential,
		s.Manifest,
		s.Presentation,
		s.Operation,
		s.Webhook,
	}
}

func (s *SSIService) GetStorage() storage.ServiceStorage {
	return s.storage
}
