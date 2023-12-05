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

	t.Run("Nil Service", func(t *testing.T) {
		keyStoreRouter, err := NewKeyStoreRouter(nil)
		assert.Error(t, err)
		assert.Empty(t, keyStoreRouter)
		assert.Contains(t, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(t *testing.T) {
		keyStoreRouter, err := NewKeyStoreRouter(&testService{})
		assert.Error(t, err)
		assert.Empty(t, keyStoreRouter)
		assert.Contains(t, err.Error(), "could not create key store router with service type: test")
	})

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Key Store Service Test", func(t *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(t, db)

				serviceConfig := new(config.KeyStoreServiceConfig)
				keyStoreService, err := keystore.NewKeyStoreService(*serviceConfig, db)
				assert.NoError(t, err)
				assert.NotEmpty(t, keyStoreService)

				// check type and status
				assert.Equal(t, framework.KeyStore, keyStoreService.Type())
				assert.Equal(t, framework.StatusReady, keyStoreService.Status().Status)

				// store an invalid key type
				err = keyStoreService.StoreKey(context.Background(), keystore.StoreKeyRequest{
					ID:               "test-kid",
					Type:             "bad",
					Controller:       "me",
					PrivateKeyBase58: base58.Encode([]byte("bad")),
				})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported key type: bad")

				// store a valid key
				_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, privKey)

				keyID := "did:test:me#key-1"
				privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
				assert.NoError(t, err)
				err = keyStoreService.StoreKey(context.Background(), keystore.StoreKeyRequest{
					ID:               keyID,
					Type:             crypto.Ed25519,
					Controller:       "did:test:me",
					PrivateKeyBase58: base58.Encode(privKeyBytes),
				})
				assert.NoError(t, err)

				// get a key that doesn't exist
				gotDetails, err := keyStoreService.GetKeyDetails(context.Background(), keystore.GetKeyDetailsRequest{ID: "bad"})
				assert.Error(t, err)
				assert.Empty(t, gotDetails)
				assert.Contains(t, err.Error(), "could not get key details for key: bad")

				// get a key that exists
				gotDetails, err = keyStoreService.GetKeyDetails(context.Background(), keystore.GetKeyDetailsRequest{ID: keyID})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDetails)

				// make sure the details match
				assert.Equal(t, keyID, gotDetails.ID)
				assert.Equal(t, crypto.Ed25519, gotDetails.Type)
				assert.Equal(t, "did:test:me", gotDetails.Controller)

				// revoked key checks
				err = keyStoreService.RevokeKey(context.Background(), keystore.RevokeKeyRequest{ID: keyID})
				assert.NoError(t, err)
				gotDetails, err = keyStoreService.GetKeyDetails(context.Background(), keystore.GetKeyDetailsRequest{ID: keyID})
				assert.NoError(t, err)
				assert.True(t, gotDetails.Revoked)
			})
		})
	}
}
