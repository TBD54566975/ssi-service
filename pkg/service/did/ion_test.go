package did

import (
	"context"
	"fmt"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
	"gopkg.in/h2non/gock.v1"
)

func TestIONHandler(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Test Create ION Handler", func(tt *testing.T) {
				handler, err := NewIONHandler("", nil, nil)
				assert.Error(tt, err)
				assert.Empty(tt, handler)
				assert.Contains(tt, err.Error(), "baseURL cannot be empty")

				s := test.ServiceStorage(t)
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
				assert.Contains(tt, err.Error(), "invalid resolution URL")

				handler, err = NewIONHandler("https://example.com", didStorage, keystoreService)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

				assert.Equal(tt, handler.GetMethod(), did.IONMethod)
			})

			t.Run("Test Create DID", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
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

			t.Run("Test Create DID", func(tt *testing.T) {
				gock.New("https://ion.tbddev.org").
					Post("/operations").
					Reply(200)
				defer gock.Off()

				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://ion.tbddev.org", didStorage, keystoreService)
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

			t.Run("Test Get DID from storage", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
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

			t.Run("Test Get DIDs from storage", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
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

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/" + created.DID.ID).
					Reply(200).BodyString(fmt.Sprintf(`{"didDocument": {"id": "%s"}}`, created.DID.ID))
				defer gock.Off()

				// get all DIDs
				gotDIDs, err := handler.ListDIDs(context.Background(), nil)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotDIDs)
				assert.Len(tt, gotDIDs.DIDs, 1)

				// delete a did
				err = handler.SoftDeleteDID(context.Background(), DeleteDIDRequest{
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

			t.Run("Test Get DID from resolver", func(tt *testing.T) {
				// create a handler
				s := test.ServiceStorage(t)
				keystoreService := testKeyStoreService(tt, s)
				didStorage, err := NewDIDStorage(s)
				assert.NoError(tt, err)
				handler, err := NewIONHandler("https://test-ion-resolver.com", didStorage, keystoreService)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, handler)

				gock.New("https://test-ion-resolver.com").
					Get("/identifiers/did:ion:test").
					Reply(200).BodyString(`{"didDocument": {"id": "did:ion:test"}}`)
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
		})
	}
}

func testKeyStoreService(t *testing.T, db storage.ServiceStorage) *keystore.Service {
	serviceConfig := config.KeyStoreServiceConfig{
		BaseServiceConfig: &config.BaseServiceConfig{Name: "test-keystore"},
		MasterKeyPassword: "test-password",
	}

	// create a keystore service
	keystoreService, err := keystore.NewKeyStoreService(serviceConfig, db)
	require.NoError(t, err)
	require.NotEmpty(t, keystoreService)
	return keystoreService
}
