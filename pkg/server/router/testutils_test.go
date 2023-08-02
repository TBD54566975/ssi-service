package router

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"

	"github.com/tbd54566975/ssi-service/pkg/testutil"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	testServerURL = "https://ssi-service.com"
)

func TestMain(t *testing.M) {
	testutil.EnableSchemaCaching()
	config.SetAPIBase(testServerURL)
	config.SetServicePath(framework.Credential, "/credentials")
	os.Exit(t.Run())
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{}
	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}

func testDIDService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service) *did.Service {
	serviceConfig := config.DIDServiceConfig{
		Methods:                []string{"key"},
		LocalResolutionMethods: []string{"key"},
	}
	// create a did service
	didService, err := did.NewDIDService(serviceConfig, db, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, didService)
	return didService
}

func testSchemaService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service) *schema.Service {
	// create a schema service
	schemaService, err := schema.NewSchemaService(db, keyStore, did.GetResolver())
	require.NoError(t, err)
	require.NotEmpty(t, schemaService)
	return schemaService
}

func testCredentialService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, schema *schema.Service) *credential.Service {
	serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
	// create a credential service
	credentialService, err := credential.NewCredentialService(serviceConfig, db, keyStore, did.GetResolver(), schema)
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)
	return credentialService
}

func testPresentationDefinitionService(t *testing.T, db storage.ServiceStorage, didService *did.Service, schemaService *schema.Service, keyStoreService *keystore.Service) *presentation.Service {
	svc, err := presentation.NewPresentationService(db, didService.GetResolver(), schemaService, keyStoreService)
	require.NoError(t, err)
	require.NotEmpty(t, svc)
	return svc
}

func testManifestService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, credential *credential.Service, presentationSvc *presentation.Service) *manifest.Service {
	// create a manifest service
	manifestService, err := manifest.NewManifestService(db, keyStore, did.GetResolver(), credential, presentationSvc)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)
	return manifestService
}
