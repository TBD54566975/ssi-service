package did

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestIONHandler(t *testing.T) {
	t.Run("Test Create ION Handler", func(tt *testing.T) {
		handler, err := NewIONHandler("", nil, nil)
		assert.Error(tt, err)
		assert.Empty(tt, handler)
		assert.Contains(tt, err.Error(), "baseURL cannot be empty")

		s := setupTestDB(tt)
		keystoreService := testKeyStoreService(tt, s)
		didStorage, err := NewDIDStorage(s)
		assert.NoError(tt, err)
		handler, err = NewIONHandler("bad", nil, keystoreService)
		assert.Error(tt, err)
		assert.Empty(tt, handler)
		assert.Contains(tt, err.Error(), "storage cannot be empty")

		handler, err = NewIONHandler("bad", didStorage, nil)
		assert.Error(tt, err)
		assert.Empty(tt, handler)
		assert.Contains(tt, err.Error(), "keystore cannot be empty")

		handler, err = NewIONHandler("bad", didStorage, keystoreService)
		assert.Error(tt, err)
		assert.Empty(tt, handler)
		assert.Contains(tt, err.Error(), "invalid resolver URL")

		handler, err = NewIONHandler("https://example.com", didStorage, keystoreService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, handler)

		assert.Equal(tt, handler.GetMethod(), did.IONMethod)
	})

	t.Run("Test Create DIDs", func(tt *testing.T) {
		// create a handler
		s := setupTestDB(tt)
		keystoreService := testKeyStoreService(tt, s)
		didStorage, err := NewDIDStorage(s)
		assert.NoError(tt, err)
		handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, handler)

		gock.New("https://test-ion-resolver.com").
			Post("/operations").
			Reply(200)
		defer gock.Off()

		// create a did
		created, err := handler.CreateDID(context.Background(), CreateDIDRequest{
			Method:  did.IONMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, created)
	})
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{
		BaseServiceConfig:  &config.BaseServiceConfig{Name: "test-keystore"},
		ServiceKeyPassword: "test-password",
	}

	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}
