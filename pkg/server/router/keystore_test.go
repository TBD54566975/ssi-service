package router

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestKeyStoreRouter(t *testing.T) {

	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Nil Service", func(tt *testing.T) {
		keyStoreRouter, err := NewKeyStoreRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, keyStoreRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		keyStoreRouter, err := NewKeyStoreRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, keyStoreRouter)
		assert.Contains(tt, err.Error(), "could not create key store router with service type: test")
	})

	t.Run("8Key Store Service Test", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

		serviceConfig := config.KeyStoreServiceConfig{
			BaseServiceConfig:  &config.BaseServiceConfig{Name: "keystore"},
			ServiceKeyPassword: "test-password",
		}
		keyStoreService, err := keystore.NewKeyStoreService(serviceConfig, bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, keyStoreService)

		// check type and status
		assert.Equal(tt, framework.KeyStore, keyStoreService.Type())
		assert.Equal(tt, framework.StatusReady, keyStoreService.Status().Status)

		// store an invalid key type
		err = keyStoreService.StoreKey(keystore.StoreKeyRequest{
			ID:         "test-kid",
			Type:       "bad",
			Controller: "me",
			Key:        []byte("bad"),
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported key type: bad")

		// store a valid key
		_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)

		privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
		assert.NoError(tt, err)

		keyID := "did:test:me#key-1"
		err = keyStoreService.StoreKey(keystore.StoreKeyRequest{
			ID:         keyID,
			Type:       crypto.Ed25519,
			Controller: "did:test:me",
			Key:        privKeyBytes,
		})
		assert.NoError(tt, err)

		// get a key that doesn't exist
		gotDetails, err := keyStoreService.GetKeyDetails(keystore.GetKeyDetailsRequest{ID: "bad"})
		assert.Error(tt, err)
		assert.Empty(tt, gotDetails)
		assert.Contains(tt, err.Error(), "could not get key details for key: bad")

		// get a key that exists
		gotDetails, err = keyStoreService.GetKeyDetails(keystore.GetKeyDetailsRequest{ID: keyID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotDetails)

		// make sure the details match
		assert.Equal(tt, keyID, gotDetails.ID)
		assert.Equal(tt, crypto.Ed25519, gotDetails.Type)
		assert.Equal(tt, "did:test:me", gotDetails.Controller)
	})
}
