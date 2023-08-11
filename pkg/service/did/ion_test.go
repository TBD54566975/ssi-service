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
	"github.com/tbd54566975/ssi-service/internal/encryption"
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
			t.Run("Create ION Handler", func(tt *testing.T) {
				handler, err := NewIONHandler("", nil, nil, nil, nil)
				assert.Error(tt, err)
				assert.Empty(tt, handler)
				assert.Contains(tt, err.Error(), "baseURL cannot be empty")

				s := test.ServiceStorage(tt)
				keystoreService, _ := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err = NewIONHandler("bad", nil, keystoreService, nil, nil)
				assert.Error(tt, err)
				assert.Empty(tt, handler)
				assert.Contains(tt, err.Error(), "storage cannot be empty")

				handler, err = NewIONHandler("bad", didStorage, nil, nil, nil)
				assert.Error(tt, err)
				assert.Empty(tt, handler)
				assert.Contains(tt, err.Error(), "keystore cannot be empty")

				handler, err = NewIONHandler("bad", didStorage, keystoreService, nil, nil)
				assert.Error(tt, err)
				assert.Empty(tt, handler)
				assert.Contains(tt, err.Error(), "invalid resolution URL")

				handler, err = NewIONHandler("https://example.com", didStorage, keystoreService, nil, nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

				assert.Equal(tt, handler.GetMethod(), did.IONMethod)
			})

			t.Run("Create DID", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(tt)
				keystoreService, _ := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				publicKey, privKey, err := crypto.GenerateEd25519Key()
				require.NoError(tt, err)
				signer, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
				require.NoError(tt, err)
				jwxJWK, err := jwx.PublicKeyToPublicKeyJWK("test-kid", publicKey)
				require.NoError(tt, err)
				ionPublicKey := ion.PublicKey{
					ID:           "test-id",
					Type:         "JsonWebKey2020",
					PublicKeyJWK: *jwxJWK,
					Purposes:     []ion.PublicKeyPurpose{ion.Authentication},
				}
				ionPublicKeyData, err := json.Marshal(ionPublicKey)
				require.NoError(tt, err)
				jwsPublicKey, err := signer.SignJWS(ionPublicKeyData)
				require.NoError(tt, err)

				// create a did
				createDIDRequest := CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
					Options: CreateIONDIDOptions{
						ServiceEndpoints: []did.Service{},
						JWSPublicKeys:    []string{string(jwsPublicKey)},
					},
				}

				tt.Run("good input returns no error", func(t *testing.T) {
					created, err := handler.CreateDID(context.Background(), createDIDRequest)
					assert.NoError(tt, err)
					assert.NotEmpty(tt, created)
				})

				tt.Run("signing with another key returns error", func(ttt *testing.T) {
					a := createDIDRequest
					_, privKey, err := crypto.GenerateEd25519Key()
					require.NoError(ttt, err)
					signer2, err := jwx.NewJWXSigner("test-id", "test-kid", privKey)
					require.NoError(ttt, err)
					signedWithOtherKey, err := signer2.SignJWS(ionPublicKeyData)
					require.NoError(ttt, err)
					a.Options.(CreateIONDIDOptions).JWSPublicKeys[0] = string(signedWithOtherKey)

					_, err = handler.CreateDID(context.Background(), createDIDRequest)

					assert.Error(ttt, err)
					assert.ErrorContains(ttt, err, "verifying JWS for")
				})
			})

			t.Run("Get a Created DID", func(tt *testing.T) {
				gock.New("https://ion.tbddev.org").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				// create a handler
				s := test.ServiceStorage(tt)
				keystoreService, _ := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://ion.tbddev.org", didStorage, keystoreService, nil, nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

				// create a did
				created, err := handler.CreateDID(context.Background(), CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, created)

				// get the did
				gotDID, err := handler.GetDID(context.Background(), GetDIDRequest{
					Method: did.IONMethod,
					ID:     created.DID.ID,
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDID)
			})

			t.Run("Get DID from storage", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(tt)
				keystoreService, _ := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

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
				assert.NoError(tt, err)
				assert.NotEmpty(tt, created)

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/" + created.DID.ID).
					Reply(200).BodyString(fmt.Sprintf(`{"didDocument": {"id": "%s"}}`, created.DID.ID))
				defer gock.Off()

				// get the did
				gotDID, err := handler.GetDID(context.Background(), GetDIDRequest{
					Method: did.IONMethod,
					ID:     created.DID.ID,
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDID)
				assert.Equal(tt, created.DID.ID, gotDID.DID.ID)
			})

			t.Run("Get DIDs from storage", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(tt)
				keystoreService, keystoreServiceFactory := testKeyStoreService(tt, s)
				didStorageFactory := NewDIDStorageFactory(s)
				didStorage, err := didStorageFactory(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, keystoreServiceFactory, didStorageFactory)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

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
				assert.NoError(tt, err)
				assert.NotEmpty(tt, created)

				createdDIDData, err := json.Marshal(created.DID)
				assert.NoError(tt, err)

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/" + created.DID.ID).
					Reply(200).BodyString(fmt.Sprintf(`{"didDocument": %s }`, createdDIDData))
				defer gock.Off()

				// get all DIDs
				gotDIDs, err := handler.ListDIDs(context.Background(), nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDIDs)
				assert.Len(tt, gotDIDs.DIDs, 1)

				// delete a did
				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					JSON(`{}`)
				defer gock.Off()
				_, err = handler.DeleteDID(context.Background(), DeleteDIDRequest{
					Method: did.IONMethod,
					ID:     created.DID.ID,
				})
				assert.NoError(tt, err)

				// get all DIDs after deleting
				gotDIDsAfterDelete, err := handler.ListDIDs(context.Background(), nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDIDs)
				assert.Len(tt, gotDIDsAfterDelete.DIDs, 0)

				// get all deleted DIDs after delete
				gotDeletedDIDs, err := handler.ListDeletedDIDs(context.Background())
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDIDs)
				assert.Len(tt, gotDeletedDIDs.DIDs, 1)
			})

			t.Run("Get DID from resolver", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(tt)
				keystoreService, _ := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, nil, nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

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
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDID)
				assert.Equal(tt, "did:ion:test", gotDID.DID.ID)
			})

			t.Run("Deactivate DID", func(tt *testing.T) {
				s := test.ServiceStorage(tt)
				keystoreService, keystoreServiceFactory := testKeyStoreService(tt, s)
				didStorageFactory := NewDIDStorageFactory(s)
				didStorage, err := didStorageFactory(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService, keystoreServiceFactory, didStorageFactory)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				createDIDRequest := CreateDIDRequest{
					Method:  did.IONMethod,
					KeyType: crypto.Ed25519,
				}
				created, err := handler.CreateDID(context.Background(), createDIDRequest)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, created)

				gock.New("https://test-ion-resolver.com").
					Post("/operations").
					Reply(200).
					JSON(`{}`)
				defer gock.Off()

				request := DeactivateIONDIDRequest{
					DID: ion.ION(created.DID.ID),
				}
				resp, err := handler.(*ionHandler).DeactivateDID(context.Background(), request)

				assert.NoError(tt, err)
				assert.NotEmpty(tt, resp)
				assert.Equal(tt, created.DID.ID, resp.Result.Document.ID)
				assert.Empty(tt, resp.Result.Document.VerificationMethod)
				assert.Empty(tt, resp.Result.Document.Authentication)
				assert.Empty(tt, resp.Result.Document.AssertionMethod)
				assert.Empty(tt, resp.Result.Document.CapabilityInvocation)
				assert.Empty(tt, resp.Result.Document.CapabilityDelegation)
				assert.Empty(tt, resp.Result.Document.KeyAgreement)

				// And the some keys were revoked.
				updateKey, err := keystoreService.GetKey(context.Background(), keystore.GetKeyRequest{ID: created.DID.ID + "#update"})
				assert.NoError(tt, err)
				assert.True(tt, updateKey.Revoked)
				recoveryKey, err := keystoreService.GetKey(context.Background(), keystore.GetKeyRequest{ID: created.DID.ID + "#recover"})
				assert.NoError(tt, err)
				assert.True(tt, recoveryKey.Revoked)
				signingKey, err := keystoreService.GetKey(context.Background(), keystore.GetKeyRequest{ID: created.DID.ID + "#recover"})
				assert.NoError(tt, err)
				assert.True(tt, signingKey.Revoked)

				t.Run("is idempotent", func(t *testing.T) {
					resp2, err := handler.(*ionHandler).DeactivateDID(context.Background(), request)
					assert.NoError(t, err)
					assert.Equal(t, resp, resp2)
				})
			})
		})
	}
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) (*keystore.Service, keystore.ServiceFactory) {
	serviceConfig := new(config.KeyStoreServiceConfig)

	factory := keystore.NewKeyStoreServiceFactory(*serviceConfig, db, encryption.NoopEncrypter, encryption.NoopDecrypter)
	// create a keystore service
	keystoreService, err := factory(db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService, factory
}
