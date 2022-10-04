package router

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func testKeyStoreService(t *testing.T, db *storage.BoltDB) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{ServiceKeyPassword: "test-password"}
	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}

func testDIDService(t *testing.T, db *storage.BoltDB, keyStore *keystore.Service) *did.Service {
	serviceConfig := config.DIDServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "did"}, Methods: []string{"key"}}
	// create a did service
	didService, err := did.NewDIDService(serviceConfig, db, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, didService)
	return didService
}

func testCredentialService(t *testing.T, db *storage.BoltDB, keyStore *keystore.Service) *credential.Service {
	serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}
	// create a credential service
	credentialService, err := credential.NewCredentialService(serviceConfig, db, keyStore)
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)
	return credentialService
}

func testManifestService(t *testing.T, db *storage.BoltDB, keyStore *keystore.Service, credential *credential.Service) *manifest.Service {
	serviceConfig := config.ManifestServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "manifest"}}
	// create a manifest service
	manifestService, err := manifest.NewManifestService(serviceConfig, db, keyStore, credential)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)
	return manifestService
}
