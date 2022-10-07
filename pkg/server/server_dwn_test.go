package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestDWNAPI(t *testing.T) {
	t.Run("Test DWN Publish Manifest", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService)
		manifestRouter, manifestService := testManifest(tt, bolt, keyStoreService, credentialService)
		dwnService := testDWNRouter(tt, bolt, keyStoreService, manifestService)

		w := httptest.NewRecorder()

		// create an issuer
		issuerDIDDoc, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDIDDoc)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDIDDoc.DID.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w = httptest.NewRecorder()

		dwnRequest := router.PublishManifestRequest{ManifestID: "WA-DL-CLASS-A"}
		dwnRequestValue := newRequestValue(tt, dwnRequest)
		dwnReq := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dwn/manifests", dwnRequestValue)
		err = dwnService.PublishManifest(newRequestContext(), w, dwnReq)

		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "unsupported protocol scheme")
	})
}
