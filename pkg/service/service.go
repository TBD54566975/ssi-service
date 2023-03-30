package service

import (
	"context"
	"fmt"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/issuing"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/oidc"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

// SSIService represents all services and their dependencies independent of transport
type SSIService struct {
	services []framework.Service
}

// InstantiateSSIService creates a new instance of the SSIS which instantiates all services and their
// dependencies independent of transport.
func InstantiateSSIService(config config.ServicesConfig) (*SSIService, error) {
	if err := validateServiceConfig(config); err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate SSI Service, invalid config")
	}
	services, err := instantiateServices(config)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not instantiate the ssi service")
	}
	return &SSIService{services: services}, nil
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
	if config.IssuingServiceConfig.IsEmpty() {
		return fmt.Errorf("%s no config provided", framework.Issuing)
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

// GetServices returns the instantiated service providers
func (ssi *SSIService) GetServices() []framework.Service {
	return ssi.services
}

// GetService returns the specified instantiated service provider
func (ssi *SSIService) GetService(serviceType framework.Type) framework.Service {
	for _, s := range ssi.services {
		if s.Type() == serviceType {
			return s
		}
	}
	return nil
}

// instantiateServices begins all instantiates and their dependencies
func instantiateServices(config config.ServicesConfig) ([]framework.Service, error) {
	storageProvider, err := storage.NewStorage(storage.Type(config.StorageProvider), config.StorageOption)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not instantiate storage provider: %s", config.StorageProvider)
	}

	webhookService, err := webhook.NewWebhookService(config.WebhookConfig, storageProvider)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the webhook service")
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

	issuingService, err := issuing.NewIssuingService(config.IssuingServiceConfig, storageProvider)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the issuing service")
	}

	credentialService, err := credential.NewCredentialService(config.CredentialConfig, storageProvider, keyStoreService, didResolver, schemaService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the credential service")
	}

	manifestService, err := manifest.NewManifestService(config.ManifestConfig, storageProvider, keyStoreService, didResolver, credentialService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the manifest service")
	}

	presentationService, err := presentation.NewPresentationService(config.PresentationConfig, storageProvider, didResolver, schemaService, keyStoreService)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the presentation service")
	}

	operationService, err := operation.NewOperationService(storageProvider)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate the operation service")
	}

	opts := make([]oidc.Option, 0)

	if config.OIDCCredentialConfig.CNonceExpiresIn != nil {
		opts = append(opts, oidc.WithCNonceExpiresIn(*config.OIDCCredentialConfig.CNonceExpiresIn))
	}
	serviceKey, err := keyStoreService.GetServiceKey(context.Background())
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not get service key")
	}
	var serviceKeyArr [32]byte
	copy(serviceKeyArr[:], serviceKey)
	oidcService := oidc.NewOIDCService(didResolver, credentialService, serviceKeyArr, opts...)

	return []framework.Service{keyStoreService, didService, schemaService, issuingService, credentialService, manifestService, presentationService, operationService, webhookService, oidcService}, nil
}
