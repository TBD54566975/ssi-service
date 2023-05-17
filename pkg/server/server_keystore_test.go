package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
)

func TestKeyStoreAPI(t *testing.T) {
	t.Run("Test Store Key", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreRouter, _ := testKeyStore(tt, bolt)
		w := httptest.NewRecorder()

		// bad key type
		badKeyStoreRequest := router.StoreKeyRequest{
			ID:               "test-kid",
			Type:             "bad",
			Controller:       "me",
			PrivateKeyBase58: "bad",
		}
		badRequestValue := newRequestValue(tt, badKeyStoreRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", badRequestValue)

		c := newRequestContext(w, req)
		err := keyStoreRouter.StoreKey(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported key type: bad")

		// store a valid key
		_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)

		privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
		assert.NoError(tt, err)

		// good request
		storeKeyRequest := router.StoreKeyRequest{
			ID:               "did:test:me#key-1",
			Type:             crypto.Ed25519,
			Controller:       "did:test:me",
			PrivateKeyBase58: base58.Encode(privKeyBytes),
		}
		requestValue := newRequestValue(tt, storeKeyRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
		w = httptest.NewRecorder()
		c = newRequestContext(w, req)
		err = keyStoreRouter.StoreKey(c)
		assert.NoError(tt, err)
	})

	t.Run("Test Get Key Details", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService, _ := testKeyStore(tt, bolt)
		w := httptest.NewRecorder()

		// store a valid key
		_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)

		privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
		assert.NoError(tt, err)

		// good request
		keyID := "did:test:me#key-2"
		controller := "did:test:me"
		storeKeyRequest := router.StoreKeyRequest{
			ID:               keyID,
			Type:             crypto.Ed25519,
			Controller:       controller,
			PrivateKeyBase58: base58.Encode(privKeyBytes),
		}
		requestValue := newRequestValue(tt, storeKeyRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
		c := newRequestContext(w, req)
		err = keyStoreService.StoreKey(c)
		assert.NoError(tt, err)

		// get it back
		w = httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/keys/%s", keyID), nil)
		c = newRequestContextWithParams(w, getReq, map[string]string{"id": keyID})
		err = keyStoreService.GetKeyDetails(c)
		assert.NoError(tt, err)

		var resp router.GetKeyDetailsResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Equal(tt, keyID, resp.ID)
		assert.Equal(tt, controller, resp.Controller)
		assert.Equal(tt, crypto.Ed25519, resp.Type)
	})
}
