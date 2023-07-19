package router

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/pkg/testutil"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
)

func TestKeyStoreRouter(t *testing.T) {

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

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Key Store Service Test", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				assert.NotEmpty(tt, db)

				serviceConfig := config.KeyStoreServiceConfig{
					BaseServiceConfig: &config.BaseServiceConfig{Name: "keystore"},
				}
				keyStoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, keyStoreService)

				// check type and status
				assert.Equal(tt, framework.KeyStore, keyStoreService.Type())
				assert.Equal(tt, framework.StatusReady, keyStoreService.Status().Status)

				// store an invalid key type
				err = keyStoreService.StoreKey(context.Background(), keystore.StoreKeyRequest{
					ID:               "test-kid",
					Type:             "bad",
					Controller:       "me",
					PrivateKeyBase58: base58.Encode([]byte("bad")),
				})
				assert.Error(tt, err)
				assert.Contains(tt, err.Error(), "unsupported key type: bad")

				// store a valid key
				_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, privKey)

				keyID := "did:test:me#key-1"
				privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
				assert.NoError(tt, err)
				err = keyStoreService.StoreKey(context.Background(), keystore.StoreKeyRequest{
					ID:               keyID,
					Type:             crypto.Ed25519,
					Controller:       "did:test:me",
					PrivateKeyBase58: base58.Encode(privKeyBytes),
				})
				assert.NoError(tt, err)

				// get a key that doesn't exist
				gotDetails, err := keyStoreService.GetKeyDetails(context.Background(), keystore.GetKeyDetailsRequest{ID: "bad"})
				assert.Error(tt, err)
				assert.Empty(tt, gotDetails)
				assert.Contains(tt, err.Error(), "could not get key details for key: bad")

				// get a key that exists
				gotDetails, err = keyStoreService.GetKeyDetails(context.Background(), keystore.GetKeyDetailsRequest{ID: keyID})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDetails)

				// make sure the details match
				assert.Equal(tt, keyID, gotDetails.ID)
				assert.Equal(tt, crypto.Ed25519, gotDetails.Type)
				assert.Equal(tt, "did:test:me", gotDetails.Controller)

				// revoked key checks
				err = keyStoreService.RevokeKey(context.Background(), keystore.RevokeKeyRequest{ID: keyID})
				assert.NoError(tt, err)
				gotDetails, err = keyStoreService.GetKeyDetails(context.Background(), keystore.GetKeyDetailsRequest{ID: keyID})
				assert.NoError(tt, err)
				assert.True(tt, gotDetails.Revoked)
			})
		})
	}
}
