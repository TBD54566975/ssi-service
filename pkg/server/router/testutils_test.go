package router

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/testutil"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestMain(t *testing.M) {
	testutil.EnableSchemaCaching()
	os.Exit(t.Run())
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{ServiceKeyPassword: "test-password"}
	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}

func testDIDService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service) *did.Service {
	serviceConfig := config.DIDServiceConfig{
		BaseServiceConfig: &config.BaseServiceConfig{
			Name: "did",
		},
		Methods:           []string{"key"},
		ResolutionMethods: []string{"key"},
	}
	// create a did service
	didService, err := did.NewDIDService(serviceConfig, db, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, didService)
	return didService
}

func testSchemaService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service) *schema.Service {
	serviceConfig := config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "schema"}}
	// create a schema service
	schemaService, err := schema.NewSchemaService(serviceConfig, db, keyStore, did.GetResolver())
	require.NoError(t, err)
	require.NotEmpty(t, schemaService)
	return schemaService
}

func testCredentialService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, schema *schema.Service) *credential.Service {
	serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}
	// create a credential service
	credentialService, err := credential.NewCredentialService(serviceConfig, db, keyStore, did.GetResolver(), schema)
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)
	return credentialService
}

func testManifestService(t *testing.T, db storage.ServiceStorage, keyStore *keystore.Service, did *did.Service, credential *credential.Service) *manifest.Service {
	serviceConfig := config.ManifestServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "manifest"}}
	// create a manifest service
	manifestService, err := manifest.NewManifestService(serviceConfig, db, keyStore, did.GetResolver(), credential)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)
	return manifestService
}
