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

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestKeyStoreAPI(t *testing.T) {

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Test Store Key", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreRouter, _, _ := testKeyStore(t, db)
				w := httptest.NewRecorder()

				// bad key type
				badKeyStoreRequest := router.StoreKeyRequest{
					ID:               "test-kid",
					Type:             "bad",
					Controller:       "me",
					PrivateKeyBase58: "bad",
				}
				badRequestValue := newRequestValue(t, badKeyStoreRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", badRequestValue)

				c := newRequestContext(w, req)
				keyStoreRouter.StoreKey(c)
				assert.Contains(t, w.Body.String(), "unsupported key type: bad")

				// store a valid key
				_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, privKey)

				privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
				assert.NoError(t, err)

				// good request
				storeKeyRequest := router.StoreKeyRequest{
					ID:               "did:test:me#key-1",
					Type:             crypto.Ed25519,
					Controller:       "did:test:me",
					PrivateKeyBase58: base58.Encode(privKeyBytes),
				}
				requestValue := newRequestValue(t, storeKeyRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
				w = httptest.NewRecorder()
				c = newRequestContext(w, req)
				keyStoreRouter.StoreKey(c)
				assert.True(t, util.Is2xxResponse(w.Code))
			})

			t.Run("Test Get Key Details", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _, _ := testKeyStore(t, db)
				w := httptest.NewRecorder()

				// store a valid key
				pubKey, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
				assert.NoError(t, err)
				assert.NotEmpty(t, privKey)

				privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
				assert.NoError(t, err)

				// good request
				keyID := "did:test:me#key-2"
				controller := "did:test:me"
				storeKeyRequest := router.StoreKeyRequest{
					ID:               keyID,
					Type:             crypto.Ed25519,
					Controller:       controller,
					PrivateKeyBase58: base58.Encode(privKeyBytes),
				}
				requestValue := newRequestValue(t, storeKeyRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
				c := newRequestContext(w, req)
				keyStoreService.StoreKey(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				// get it back
				w = httptest.NewRecorder()
				getReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/keys/%s", keyID), nil)
				c = newRequestContextWithParams(w, getReq, map[string]string{"id": keyID})
				keyStoreService.GetKeyDetails(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.GetKeyDetailsResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.Equal(t, keyID, resp.ID)
				assert.Equal(t, controller, resp.Controller)
				assert.Equal(t, crypto.Ed25519, resp.Type)

				gotPubKey, err := resp.PublicKeyJWK.ToPublicKey()
				assert.NoError(t, err)
				wantPubKey, err := crypto.PubKeyToBytes(pubKey)
				assert.NoError(t, err)
				assert.NotEmpty(t, wantPubKey, gotPubKey)
			})
		})
	}
}
