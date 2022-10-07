package router

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestDIDRouter(t *testing.T) {

	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Nil Service", func(tt *testing.T) {
		didRouter, err := NewDIDRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, didRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		didRouter, err := NewDIDRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, didRouter)
		assert.Contains(tt, err.Error(), "could not create DID router with service type: test")
	})

	t.Run("DID Service Test", func(tt *testing.T) {
		db, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, db)

		keyStoreService := testKeyStoreService(tt, db)
		methods := []string{didsdk.KeyMethod.String()}
		serviceConfig := config.DIDServiceConfig{Methods: methods, ResolutionMethods: methods}
		didService, err := did.NewDIDService(serviceConfig, db, keyStoreService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, didService)

		// check type and status
		assert.Equal(tt, framework.DID, didService.Type())
		assert.Equal(tt, framework.StatusReady, didService.Status().Status)

		// get unknown handler
		_, err = didService.GetDIDByMethod(did.GetDIDRequest{Method: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get handler for method<bad>")

		supported := didService.GetSupportedMethods()
		assert.NotEmpty(tt, supported)
		assert.Len(tt, supported.Methods, 1)
		assert.Equal(tt, didsdk.KeyMethod, supported.Methods[0])

		// bad key type
		_, err = didService.CreateDIDByMethod(did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create did:key")

		// good key type
		createDIDResponse, err := didService.CreateDIDByMethod(did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createDIDResponse)

		// check the DID is a did:key
		assert.Contains(tt, createDIDResponse.DID.ID, "did:key")

		// get it back
		getDIDResponse, err := didService.GetDIDByMethod(did.GetDIDRequest{Method: didsdk.KeyMethod, ID: createDIDResponse.DID.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getDIDResponse)

		// make sure it's the same value
		assert.Equal(tt, createDIDResponse.DID.ID, getDIDResponse.DID.ID)

		// create a second DID
		createDIDResponse2, err := didService.CreateDIDByMethod(did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createDIDResponse2)

		// get all DIDs back
		getDIDsResponse, err := didService.GetDIDsByMethod(did.GetDIDsRequest{Method: didsdk.KeyMethod})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getDIDsResponse)
		assert.Len(tt, getDIDsResponse.DIDs, 2)

		knownDIDs := map[string]bool{createDIDResponse.DID.ID: true, createDIDResponse2.DID.ID: true}
		for _, did := range getDIDsResponse.DIDs {
			if _, ok := knownDIDs[did.ID]; !ok {
				tt.Error("got unknown DID")
			} else {
				delete(knownDIDs, did.ID)
			}
		}
		assert.Len(tt, knownDIDs, 0)
	})
}
