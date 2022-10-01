package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestKeyStoreAPI(t *testing.T) {
	t.Run("Test Store Key", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreRouter, _ := testKeyStore(tt, bolt)
		w := httptest.NewRecorder()

		// bad key type
		badKeyStoreRequest := router.StoreKeyRequest{
			ID:               "test-kid",
			Type:             "bad",
			Controller:       "me",
			Base58PrivateKey: "bad",
		}
		badRequestValue := newRequestValue(tt, badKeyStoreRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", badRequestValue)
		err = keyStoreRouter.StoreKey(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported key type: bad")

		// reset the http recorder
		w.Flush()

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
			Base58PrivateKey: base58.Encode(privKeyBytes),
		}
		requestValue := newRequestValue(tt, storeKeyRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
		err = keyStoreRouter.StoreKey(newRequestContext(), w, req)
		assert.NoError(tt, err)
	})

	t.Run("Test Get Key Details", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

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
			Base58PrivateKey: base58.Encode(privKeyBytes),
		}
		requestValue := newRequestValue(tt, storeKeyRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
		err = keyStoreService.StoreKey(newRequestContext(), w, req)
		assert.NoError(tt, err)

		// get it back
		getRecorder := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/keys/%s", keyID), nil)
		err = keyStoreService.GetKeyDetails(newRequestContextWithParams(map[string]string{"id": keyID}), getRecorder, getReq)
		assert.NoError(tt, err)

		var resp router.GetKeyDetailsResponse
		err = json.NewDecoder(getRecorder.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Equal(tt, keyID, resp.ID)
		assert.Equal(tt, controller, resp.Controller)
		assert.Equal(tt, crypto.Ed25519, resp.Type)
	})
}
