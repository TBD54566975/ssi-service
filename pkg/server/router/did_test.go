package router

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
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
		serviceConfig := config.DIDServiceConfig{Methods: []string{string(did.KeyMethod)}}
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
		assert.Equal(tt, did.KeyMethod, supported.Methods[0])

		// bad key type
		_, err = didService.CreateDIDByMethod(did.CreateDIDRequest{Method: did.KeyMethod, KeyType: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create did:key")

		// good key type
		createDIDResponse, err := didService.CreateDIDByMethod(did.CreateDIDRequest{Method: did.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createDIDResponse)

		// check the DID is a did:key
		assert.Contains(tt, createDIDResponse.DID.ID, "did:key")

		// get it back
		getDIDResponse, err := didService.GetDIDByMethod(did.GetDIDRequest{Method: did.KeyMethod, ID: createDIDResponse.DID.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getDIDResponse)

		// make sure it's the same value
		assert.Equal(tt, createDIDResponse.DID.ID, getDIDResponse.DID.ID)
	})
}
