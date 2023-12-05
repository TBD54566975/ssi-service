package did

import (
	"context"
	_ "embed"
	"fmt"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

//go:embed testdata/basic_did_resolution.json
var BasicDIDResolution []byte

func TestIONHandler(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Create ION Handler", func(t *testing.T) {
				handler, err := NewIONHandler("", nil, nil, nil, nil)
				assert.Error(t, err)
				assert.Empty(t, handler)
				assert.Contains(t, err.Error(), "baseURL cannot be empty")

				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(t, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(t, err)
				handler, err = NewIONHandler("bad", nil, keystoreService, nil, nil)
				assert.Error(t, err)
				assert.Empty(t, handler)
				assert.Contains(t, err.Error(), "storage cannot be empty")

				handler, err = NewIONHandler("bad", didStorage, nil, nil, nil)
				assert.Error(t, err)
				assert.Empty(t, handler)
				assert.Contains(t, err.Error(), "keystore cannot be empty")

				handler, err = NewIONHandler("bad", didStorage, keystoreService, nil, nil)
				assert.Error(t, err)
				assert.Empty(t, handler)
				assert.Contains(t, err.Error(), "invalid resolution URL")

				handler, err = NewIONHandler("https://example.com", didStorage, keystoreService, nil, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, handler)

				assert.Equal(t, handler.GetMethod(), did.IONMethod)
			})

			t.Run("Create DID", func(t *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(t, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(t, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, handler)

				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				publicKey, privKey, err := crypto.GenerateEd25519Key()
				require.NoError(t, err)
				signer, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
				require.NoError(t, err)
				jwxJWK, err := jwx.PublicKeyToPublicKeyJWK("test-kid", publicKey)
				require.NoError(t, err)
				ionPublicKey := ion.PublicKey{
					ID:           "test-id",
					Type:         "JsonWebKey2020",
					PublicKeyJWK: *jwxJWK,
					Purposes:     []did.PublicKeyPurpose{did.Authentication},
				}
				ionPublicKeyData, err := json.Marshal(ionPublicKey)
				require.NoError(t, err)
				jwsPublicKey, err := signer.SignJWS(ionPublicKeyData)
				require.NoError(t, err)

				// create a did
				createDIDRequest := CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
					Options: CreateIONDIDOptions{
						ServiceEndpoints: []did.Service{},
						JWSPublicKeys:    []string{string(jwsPublicKey)},
					},
				}

				t.Run("good input returns no error", func(t *testing.T) {
					created, err := handler.CreateDID(context.Background(), createDIDRequest)
					assert.NoError(t, err)
					assert.NotEmpty(t, created)
				})

				t.Run("signing with another key returns error", func(t *testing.T) {
					a := createDIDRequest
					_, privKey, err := crypto.GenerateEd25519Key()
					require.NoError(t, err)
					signer2, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
					require.NoError(t, err)
					signedWithOtherKey, err := signer2.SignJWS(ionPublicKeyData)
					require.NoError(t, err)
					a.Options.(CreateIONDIDOptions).JWSPublicKeys[0] = string(signedWithOtherKey)

					_, err = handler.CreateDID(context.Background(), createDIDRequest)

					assert.Error(t, err)
					assert.ErrorContains(t, err, "verifying JWS for")
				})
			})

			t.Run("Get a Created DID", func(t *testing.T) {
				gock.New("https://ion.tbddev.org").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(t, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(t, err)
				handler, err := NewIONHandler("https://ion.tbddev.org", didStorage, keystoreService, nil, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, handler)

				// create a did
				created, err := handler.CreateDID(context.Background(), CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, created)

				// get the did
				gotDID, err := handler.GetDID(context.Background(), GetDIDRequest{
					Method: did.IONMethod,
					ID:     created.DID.ID,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDID)
			})

			t.Run("Get DID from storage", func(t *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(t, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(t, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, handler)

				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				// create a did
				created, err := handler.CreateDID(context.Background(), CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, created)

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/" + created.DID.ID).
					Reply(200).BodyString(fmt.Sprintf(`{"didDocument": {"id": "%s"}}`, created.DID.ID))
				defer gock.Off()

				// get the did
				gotDID, err := handler.GetDID(context.Background(), GetDIDRequest{
					Method: did.IONMethod,
					ID:     created.DID.ID,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDID)
				assert.Equal(t, created.DID.ID, gotDID.DID.ID)
			})

			t.Run("Get DIDs from storage", func(t *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(t, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(t, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, handler)

				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				// create a did
				created, err := handler.CreateDID(context.Background(), CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, created)

				createdDIDData, err := json.Marshal(created.DID)
				assert.NoError(t, err)

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/" + created.DID.ID).
					Reply(200).BodyString(fmt.Sprintf(`{"didDocument": %s }`, createdDIDData))
				defer gock.Off()

				// get all DIDs
				gotDIDs, err := handler.ListDIDs(context.Background(), nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDIDs)
				assert.Len(t, gotDIDs.DIDs, 1)

				// delete a did
				err = handler.SoftDeleteDID(context.Background(), DeleteDIDRequest{
					Method: did.IONMethod,
					ID:     created.DID.ID,
				})
				assert.NoError(t, err)

				// get all DIDs after deleting
				gotDIDsAfterDelete, err := handler.ListDIDs(context.Background(), nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDIDs)
				assert.Len(t, gotDIDsAfterDelete.DIDs, 0)

				// get all deleted DIDs after delete
				gotDeletedDIDs, err := handler.ListDeletedDIDs(context.Background())
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDIDs)
				assert.Len(t, gotDeletedDIDs.DIDs, 1)
			})

			t.Run("Get DID from resolver", func(t *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(t, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(t, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(t, err)
				assert.NotEmpty(t, handler)

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/did:ion:test").
					Reply(200).
					BodyString(`{"didDocument": {"id": "did:ion:test"}}`)
				defer gock.Off()

				// get the did
				gotDID, err := handler.GetDID(context.Background(), GetDIDRequest{
					Method: did.IONMethod,
					ID:     "did:ion:test",
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotDID)
				assert.Equal(t, "did:ion:test", gotDID.DID.ID)
			})
		})
	}
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := new(config.KeyStoreServiceConfig)

	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(*serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}
