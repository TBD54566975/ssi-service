package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
)

func TestDIDAPI(t *testing.T) {
	t.Run("Test Get DID Methods", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStoreService := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStoreService, []string{"key", "web", "ion"})

		// get DID method
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids", nil)
		w := httptest.NewRecorder()

		err := didService.GetDIDMethods(newRequestContext(), w, req)
		assert.NoError(tt, err)
		assert.Equal(tt, http.StatusOK, w.Result().StatusCode)

		var resp router.GetDIDMethodsResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Len(tt, resp.DIDMethods, 3)
		assert.Contains(tt, resp.DIDMethods, didsdk.KeyMethod)
		assert.Contains(tt, resp.DIDMethods, didsdk.WebMethod)
		assert.Contains(tt, resp.DIDMethods, didsdk.IONMethod)
	})

	t.Run("Test Create DID By Method: Key", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStoreService := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStoreService, []string{"key"})

		// create DID by method - key - missing body
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", nil)
		w := httptest.NewRecorder()
		params := map[string]string{
			"method": "key",
		}

		err := didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create DID request")

		// reset recorder between calls
		w.Flush()

		// with body, bad key type
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: "bad"}
		requestReader := newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create DID for method<key> with key type: bad")

		// reset recorder between calls
		w.Flush()

		// with body, good key type
		createDIDRequest = router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var resp router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Contains(tt, resp.DID.ID, didsdk.KeyMethod)
	})

	t.Run("Test Create DID By Method: Web", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStoreService := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStoreService, []string{"web"})

		// create DID by method - web - missing body
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", nil)
		w := httptest.NewRecorder()
		params := map[string]string{
			"method": "web",
		}

		err := didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create DID request")

		// reset recorder between calls
		w.Flush()

		// with body, good key type, missing options
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create DID for method<web> with key type: Ed25519: options cannot be empty")

		// reset recorder between calls
		w.Flush()

		// good options
		options := did.CreateWebDIDOptions{DIDWebID: "did:web:example.com"}

		// with body, bad key type
		createDIDRequest = router.CreateDIDByMethodRequest{KeyType: "bad", Options: options}
		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create DID for method<web> with key type: bad")

		// reset recorder between calls
		w.Flush()

		// with body, good key type with options
		createDIDRequest = router.CreateDIDByMethodRequest{
			KeyType: crypto.Ed25519,
			Options: options,
		}

		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader)

		gock.New("https://example.com").
			Get("/.well-known/did.json").
			Reply(200).
			BodyString(`{"didDocument": {"id": "did:web:example.com"}}`)
		defer gock.Off()

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var resp router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Contains(tt, resp.DID.ID, didsdk.WebMethod)
	})

	t.Run("Test Create DID By Method: ION", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStoreService := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStoreService, []string{"ion"})

		// create DID by method - ion - missing body
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", nil)
		w := httptest.NewRecorder()
		params := map[string]string{
			"method": "ion",
		}

		err := didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create DID request")

		// reset recorder between calls
		w.Flush()

		gock.New(testIONResolverURL).
			Post("/operations").
			Reply(200)
		defer gock.Off()

		// with body, good key type, no options
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		// reset recorder between calls
		w.Flush()

		// good options
		options := did.CreateIONDIDOptions{ServiceEndpoints: []ion.Service{{ID: "test", Type: "test", ServiceEndpoint: "test"}}}

		// with body, bad key type
		createDIDRequest = router.CreateDIDByMethodRequest{KeyType: "bad", Options: options}
		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create DID for method<ion> with key type: bad")

		// reset recorder between calls
		w.Flush()

		// with body, good key type with options
		createDIDRequest = router.CreateDIDByMethodRequest{
			KeyType: crypto.Ed25519,
			Options: options,
		}
		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", requestReader)

		gock.New(testIONResolverURL).
			Post("/operations").
			Reply(200)
		defer gock.Off()

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var resp router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Contains(tt, resp.DID.ID, didsdk.IONMethod)
	})

	t.Run("Test Get DID By Method", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStore := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStore, []string{"key"})

		// get DID by method
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/bad/worse", nil)
		w := httptest.NewRecorder()

		// bad params
		badParams := map[string]string{
			"method": "bad",
			"id":     "worse",
		}
		err := didService.GetDIDByMethod(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get DID for method<bad>")

		// reset recorder between calls
		w.Flush()

		// good method, bad id
		badParams1 := map[string]string{
			"method": "key",
			"id":     "worse",
		}
		err = didService.GetDIDByMethod(newRequestContextWithParams(badParams1), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get DID for method<key> with id: worse")

		// reset recorder between calls
		w.Flush()

		// store a DID
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		params := map[string]string{"method": "key"}
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var createdDID router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&createdDID)
		assert.NoError(tt, err)

		// reset recorder between calls
		w.Flush()

		// get it back
		createdID := createdDID.DID.ID
		getDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
		req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)

		// good params
		goodParams := map[string]string{
			"method": "key",
			"id":     createdID,
		}
		err = didService.GetDIDByMethod(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)

		var resp router.GetDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Equal(tt, createdID, resp.DID.ID)
	})

	t.Run("Test Soft Delete DID By Method", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStore := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStore, []string{"key"})

		// soft delete DID by method
		req := httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/dids/bad/worse", nil)
		w := httptest.NewRecorder()

		// bad params
		badParams := map[string]string{
			"method": "bad",
			"id":     "worse",
		}

		err := didService.SoftDeleteDIDByMethod(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not soft delete DID")

		// good method, bad id
		badParams1 := map[string]string{
			"method": "key",
			"id":     "worse",
		}
		err = didService.SoftDeleteDIDByMethod(newRequestContextWithParams(badParams1), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not soft delete DID with id: worse: error getting DID: worse")

		// store a DID
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		params := map[string]string{"method": "key"}
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var createdDID router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&createdDID)
		assert.NoError(tt, err)

		// get all dids for method
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key", requestReader)
		err = didService.GetDIDsByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var gotDIDsResponse router.GetDIDsByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&gotDIDsResponse)
		assert.NoError(tt, err)
		assert.Len(tt, gotDIDsResponse.DIDs, 1)

		// get it back
		createdID := createdDID.DID.ID
		getDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
		req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)

		// good params
		goodParams := map[string]string{
			"method": "key",
			"id":     createdID,
		}
		err = didService.GetDIDByMethod(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)

		var resp router.GetDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Equal(tt, createdID, resp.DID.ID)

		// delete it
		deleteDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
		req = httptest.NewRequest(http.MethodDelete, deleteDIDPath, nil)

		err = didService.SoftDeleteDIDByMethod(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)

		// get it back
		req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)

		err = didService.GetDIDByMethod(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)

		var deletedGetResp router.GetDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&deletedGetResp)
		assert.NoError(tt, err)
		assert.Equal(tt, createdID, deletedGetResp.DID.ID)

		// get all dids for method
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key", requestReader)
		err = didService.GetDIDsByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var gotDIDsResponseAfterDelete router.GetDIDsByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&gotDIDsResponseAfterDelete)
		assert.NoError(tt, err)
		assert.Len(tt, gotDIDsResponseAfterDelete.DIDs, 0)
	})

	t.Run("Test Get DIDs By Method", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)
		_, keyStore := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStore, []string{"key", "web"})

		// get DIDs by method
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/bad", nil)
		w := httptest.NewRecorder()

		// bad params
		badParams := map[string]string{
			"method": "bad",
		}
		err := didService.GetDIDsByMethod(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get DIDs for method: bad")

		// good method
		goodParams := map[string]string{
			"method": "key",
		}
		err = didService.GetDIDsByMethod(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)
		var gotDIDs router.GetDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&gotDIDs)
		assert.NoError(tt, err)
		assert.Empty(tt, gotDIDs)

		// reset recorder between calls
		w.Flush()

		// store two DIDs
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		params := map[string]string{"method": "key"}
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var createdDID router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&createdDID)
		assert.NoError(tt, err)

		// reset recorder between calls
		w.Flush()

		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var createdDID2 router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&createdDID2)
		assert.NoError(tt, err)

		// reset recorder between calls
		w.Flush()

		// get all dids for method
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key", requestReader)
		err = didService.GetDIDsByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var gotDIDsResponse router.GetDIDsByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&gotDIDsResponse)
		assert.NoError(tt, err)

		knownDIDs := map[string]bool{createdDID.DID.ID: true, createdDID2.DID.ID: true}
		for _, did := range gotDIDsResponse.DIDs {
			if _, ok := knownDIDs[did.ID]; !ok {
				tt.Error("got unknown DID")
			} else {
				delete(knownDIDs, did.ID)
			}
		}
		assert.Len(tt, knownDIDs, 0)
	})

	t.Run("Test Resolve DIDs", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		_, keyStore := testKeyStore(tt, bolt)
		didService := testDIDRouter(tt, bolt, keyStore, []string{"key", "web"})

		// bad resolution request
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/resolver/bad", nil)
		w := httptest.NewRecorder()

		badParams := map[string]string{
			"id": "bad",
		}
		err := didService.ResolveDID(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "malformed did")

		w.Flush()

		// known method, bad did
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/resolver/did:key:abcd", nil)
		badParams = map[string]string{
			"id": "did:key:abcd",
		}
		err = didService.ResolveDID(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unable to resolve DID did:key:abcd")

		w.Flush()

		// known method, good did
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/resolver/did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", nil)
		goodParams := map[string]string{
			"id": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
		}
		err = didService.ResolveDID(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)

		var resolutionResponse router.ResolveDIDResponse
		err = json.NewDecoder(w.Body).Decode(&resolutionResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resolutionResponse.DIDDocument)
		assert.Equal(tt, "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", resolutionResponse.DIDDocument.ID)
	})
}
