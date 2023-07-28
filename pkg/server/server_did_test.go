package server

import (
	_ "embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
	"gopkg.in/h2non/gock.v1"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
)

//go:embed testdata/basic_did_resolution.json
var BasicDIDResolution []byte

func TestDIDAPI(t *testing.T) {

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {

			t.Run("Test Get DID Methods", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStoreService, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStoreService, []string{"key", "web", "ion"}, nil)

				// get DID method
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids", nil)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				didService.ListDIDMethods(c)
				assert.Equal(tt, http.StatusOK, w.Result().StatusCode)

				var resp router.ListDIDMethodsResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)

				assert.Len(tt, resp.DIDMethods, 3)
				assert.Contains(tt, resp.DIDMethods, didsdk.KeyMethod)
				assert.Contains(tt, resp.DIDMethods, didsdk.WebMethod)
				assert.Contains(tt, resp.DIDMethods, didsdk.IONMethod)
			})

			t.Run("Test Create DID By Method: Key", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStoreService, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStoreService, []string{"key"}, nil)

				// create DID by method - key - missing body
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", nil)
				w := httptest.NewRecorder()
				params := map[string]string{"method": "key"}
				c := newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "invalid create DID request")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// with body, bad key type
				createDIDRequest := router.CreateDIDByMethodRequest{KeyType: "bad"}
				requestReader := newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not create DID for method<key> with key type: bad")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// with body, good key type
				createDIDRequest = router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
				requestReader = newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Contains(tt, resp.DID.ID, didsdk.KeyMethod)
			})

			t.Run("Test Create DID By Method: Web", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStoreService, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStoreService, []string{"web"}, nil)

				// create DID by method - web - missing body
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", nil)
				w := httptest.NewRecorder()
				params := map[string]string{
					"method": "web",
				}

				c := newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "invalid create DID request")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// with body, good key type, missing options
				createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
				requestReader := newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not create DID for method<web> with key type: Ed25519: options cannot be empty")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// good options
				options := did.CreateWebDIDOptions{DIDWebID: "did:web:example.com"}

				// with body, bad key type
				createDIDRequest = router.CreateDIDByMethodRequest{KeyType: "bad", Options: options}
				requestReader = newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not create DID for method<web> with key type: bad")

				// reset recorder between calls
				w = httptest.NewRecorder()

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

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Contains(tt, resp.DID.ID, didsdk.WebMethod)
			})

			t.Run("Test Create DID By Method: ION", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStoreService, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStoreService, []string{"ion"}, nil)

				// create DID by method - ion - missing body
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", nil)
				w := httptest.NewRecorder()
				params := map[string]string{
					"method": "ion",
				}

				c := newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "invalid create DID request")

				// reset recorder between calls
				w = httptest.NewRecorder()

				defer gock.Off()
				gock.New(testIONResolverURL).
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))

				// with body, good key type, no options
				createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
				requestReader := newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				// reset recorder between calls
				w = httptest.NewRecorder()

				// good options
				options := did.CreateIONDIDOptions{ServiceEndpoints: []didsdk.Service{{ID: "test", Type: "test", ServiceEndpoint: "test"}}}

				// with body, bad key type
				createDIDRequest = router.CreateDIDByMethodRequest{KeyType: "bad", Options: options}
				requestReader = newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not create DID for method<ion> with key type: bad")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// with body, good key type with options
				createDIDRequest = router.CreateDIDByMethodRequest{
					KeyType: crypto.Ed25519,
					Options: options,
				}
				requestReader = newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/ion", requestReader)

				gock.New(testIONResolverURL).
					Post("/operations").
					Reply(200).
					BodyString(string(BasicDIDResolution))
				defer gock.Off()

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Contains(tt, resp.DID.ID, didsdk.IONMethod)
			})

			t.Run("Test Create Duplicate DID:Webs", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStoreService, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStoreService, []string{"web"}, nil)

				// reset recorder between calls
				w := httptest.NewRecorder()

				// good options
				options := did.CreateWebDIDOptions{DIDWebID: "did:web:example.com"}

				params := map[string]string{
					"method": "web",
				}

				// with body, good key type with options
				createDIDRequest := router.CreateDIDByMethodRequest{
					KeyType: crypto.Ed25519,
					Options: options,
				}

				requestReader := newRequestValue(tt, createDIDRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader)

				gock.New("https://example.com").
					Get("/.well-known/did.json").
					Reply(200).
					BodyString(`{"didDocument": {"id": "did:web:example.com"}}`)
				defer gock.Off()

				c := newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Contains(tt, resp.DID.ID, didsdk.WebMethod)

				// reset recorder between calls
				w = httptest.NewRecorder()

				requestReader2 := newRequestValue(tt, createDIDRequest)
				req2 := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/web", requestReader2)
				gock.New("https://example.com").
					Get("/.well-known/did.json").
					Reply(200).
					BodyString(`{"didDocument": {"id": "did:web:example.com"}}`)
				defer gock.Off()

				// Make sure it can't make another did:web of the same DIDWebID
				c = newRequestContextWithParams(w, req2, params)
				didService.CreateDIDByMethod(c)
				assert.Equal(tt, w.Code, 500)

				assert.Contains(tt, w.Body.String(), "already exists")
			})

			t.Run("Test Get DID By Method", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStore, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStore, []string{"key"}, nil)

				// get DID by method
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/bad/worse", nil)
				w := httptest.NewRecorder()

				// bad params
				badParams := map[string]string{
					"method": "bad",
					"id":     "worse",
				}
				c := newRequestContextWithParams(w, req, badParams)
				didService.GetDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not get DID for method<bad>")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// good method, bad id
				badParams1 := map[string]string{
					"method": "key",
					"id":     "worse",
				}
				c = newRequestContextWithParams(w, req, badParams1)
				didService.GetDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not get DID for method<key> with id: worse")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// store a DID
				createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
				requestReader := newRequestValue(tt, createDIDRequest)
				params := map[string]string{"method": "key"}
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var createdDID router.CreateDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&createdDID)
				assert.NoError(tt, err)

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get it back
				createdID := createdDID.DID.ID
				getDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
				req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)

				// good params
				goodParams := map[string]string{
					"method": "key",
					"id":     createdID,
				}
				c = newRequestContextWithParams(w, req, goodParams)
				didService.GetDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.GetDIDByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Equal(tt, createdID, resp.DID.ID)
			})

			t.Run("Test Soft Delete DID By Method", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStore, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStore, []string{"key"}, nil)

				// soft delete DID by method
				req := httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/dids/bad/worse", nil)
				w := httptest.NewRecorder()

				// bad params
				badParams := map[string]string{
					"method": "bad",
					"id":     "worse",
				}

				c := newRequestContextWithParams(w, req, badParams)
				didService.SoftDeleteDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not soft delete DID")

				// good method, bad id
				badParams1 := map[string]string{
					"method": "key",
					"id":     "worse",
				}
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, badParams1)
				didService.SoftDeleteDIDByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not soft delete DID with id: worse: error getting DID: worse")

				// store a DID
				createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
				requestReader := newRequestValue(tt, createDIDRequest)
				params := map[string]string{"method": "key"}
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var createdDID router.CreateDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&createdDID)
				assert.NoError(tt, err)

				// get all dids for method
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key", requestReader)
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, params)
				didService.ListDIDsByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var gotDIDsResponse router.ListDIDsByMethodResponse
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
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, goodParams)
				didService.GetDIDByMethod(c)
				assert.NoError(tt, err)

				var resp router.GetDIDByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Equal(tt, createdID, resp.DID.ID)

				// delete it
				deleteDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
				req = httptest.NewRequest(http.MethodDelete, deleteDIDPath, nil)

				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, goodParams)
				didService.SoftDeleteDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				// get it back
				req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)

				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, goodParams)
				didService.GetDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var deletedGetResp router.GetDIDByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&deletedGetResp)
				assert.NoError(tt, err)
				assert.Equal(tt, createdID, deletedGetResp.DID.ID)

				// get all dids for method
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key", requestReader)
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, params)
				didService.ListDIDsByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var gotDIDsResponseAfterDelete router.ListDIDsByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&gotDIDsResponseAfterDelete)
				assert.NoError(tt, err)
				assert.Len(tt, gotDIDsResponseAfterDelete.DIDs, 0)

				// get all deleted dids for method
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key?deleted=true", requestReader)
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, params)
				didService.ListDIDsByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var gotDeletedDIDsResponseAfterDelete router.ListDIDsByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&gotDeletedDIDsResponseAfterDelete)
				assert.NoError(tt, err)
				assert.Len(tt, gotDeletedDIDsResponseAfterDelete.DIDs, 1)
			})

			t.Run("List DIDs made up token fails", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)
				_, keyStore, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStore, []string{"key", "web"}, nil)

				w := httptest.NewRecorder()
				badParams := url.Values{
					"method":    []string{"key"},
					"pageSize":  []string{"1"},
					"pageToken": []string{"made up token"},
				}
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key?"+badParams.Encode(), nil)
				c := newRequestContextWithURLValues(w, req, badParams)
				didService.ListDIDsByMethod(c)
				assert.Contains(tt, w.Body.String(), "token value cannot be decoded")
			})

			t.Run("List DIDs pagination", func(tt *testing.T) {
				if !strings.Contains(test.Name, "Redis") {
					db := test.ServiceStorage(tt)
					require.NotEmpty(tt, db)
					_, keyStore, _ := testKeyStore(tt, db)
					didRouter, _ := testDIDRouter(tt, db, keyStore, []string{"key", "web"}, nil)

					createDIDWithRouter(tt, didRouter)
					createDIDWithRouter(tt, didRouter)

					w := httptest.NewRecorder()
					params := url.Values{
						"method":   []string{"key"},
						"pageSize": []string{"1"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key?"+params.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, params)

					didRouter.ListDIDsByMethod(c)

					var listDIDsByMethodResponse router.ListDIDsByMethodResponse
					err := json.NewDecoder(w.Body).Decode(&listDIDsByMethodResponse)
					assert.NoError(tt, err)
					assert.NotEmpty(tt, listDIDsByMethodResponse.NextPageToken)
					assert.Len(tt, listDIDsByMethodResponse.DIDs, 1)

					w = httptest.NewRecorder()
					params["pageToken"] = []string{listDIDsByMethodResponse.NextPageToken}
					req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key?"+params.Encode(), nil)
					c = newRequestContextWithURLValues(w, req, params)

					didRouter.ListDIDsByMethod(c)

					var listDIDsByMethodResponse2 router.ListDIDsByMethodResponse
					err = json.NewDecoder(w.Body).Decode(&listDIDsByMethodResponse2)
					assert.NoError(tt, err)
					assert.Empty(tt, listDIDsByMethodResponse2.NextPageToken)
					assert.Len(tt, listDIDsByMethodResponse2.DIDs, 1)
				}
			})

			t.Run("List DIDs pagination change query between calls returns error", func(tt *testing.T) {
				if !strings.Contains(test.Name, "Redis") {
					db := test.ServiceStorage(tt)
					require.NotEmpty(tt, db)
					_, keyStore, _ := testKeyStore(tt, db)
					didRouter, _ := testDIDRouter(tt, db, keyStore, []string{"key", "web"}, nil)
					createDIDWithRouter(tt, didRouter)
					createDIDWithRouter(tt, didRouter)

					w := httptest.NewRecorder()
					params := url.Values{
						"method":   []string{"key"},
						"pageSize": []string{"1"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key?"+params.Encode(), nil)

					c := newRequestContextWithURLValues(w, req, params)
					didRouter.ListDIDsByMethod(c)
					assert.True(tt, util.Is2xxResponse(w.Result().StatusCode))

					var listDIDsByMethodResponse router.ListDIDsByMethodResponse
					err := json.NewDecoder(w.Body).Decode(&listDIDsByMethodResponse)
					assert.NoError(tt, err)
					assert.NotEmpty(tt, listDIDsByMethodResponse.NextPageToken)
					assert.Len(tt, listDIDsByMethodResponse.DIDs, 1)

					w = httptest.NewRecorder()
					params["pageToken"] = []string{listDIDsByMethodResponse.NextPageToken}
					params["deleted"] = []string{"true"}
					req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key?"+params.Encode(), nil)
					c = newRequestContextWithURLValues(w, req, params)
					didRouter.ListDIDsByMethod(c)
					assert.Equal(tt, http.StatusBadRequest, w.Result().StatusCode)
					assert.Contains(tt, w.Body.String(), "page token must be for the same query")
				}
			})

			t.Run("Test Get DIDs By Method", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)
				_, keyStore, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStore, []string{"key", "web"}, nil)

				// get DIDs by method
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/bad", nil)
				w := httptest.NewRecorder()

				// bad params
				badParams := map[string]string{
					"method": "bad",
				}
				c := newRequestContextWithParams(w, req, badParams)
				didService.ListDIDsByMethod(c)
				assert.Contains(tt, w.Body.String(), "could not get DIDs for method: bad")

				w = httptest.NewRecorder()

				// good method
				goodParams := map[string]string{"method": "key"}
				c = newRequestContextWithParams(w, req, goodParams)
				didService.ListDIDsByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))
				var gotDIDs router.GetDIDByMethodResponse
				err := json.NewDecoder(w.Body).Decode(&gotDIDs)
				assert.NoError(tt, err)
				assert.Empty(tt, gotDIDs)

				// reset recorder between calls
				w = httptest.NewRecorder()

				// store two DIDs
				createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
				requestReader := newRequestValue(tt, createDIDRequest)
				params := map[string]string{"method": "key"}
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var createdDID router.CreateDIDByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&createdDID)
				assert.NoError(tt, err)

				// reset recorder between calls
				w = httptest.NewRecorder()

				requestReader = newRequestValue(tt, createDIDRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

				c = newRequestContextWithParams(w, req, params)
				didService.CreateDIDByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var createdDID2 router.CreateDIDByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&createdDID2)
				assert.NoError(tt, err)

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get all dids for method
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/key", requestReader)
				c = newRequestContextWithParams(w, req, params)
				didService.ListDIDsByMethod(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var gotDIDsResponse router.ListDIDsByMethodResponse
				err = json.NewDecoder(w.Body).Decode(&gotDIDsResponse)
				assert.NoError(tt, err)

				knownDIDs := map[string]bool{createdDID.DID.ID: true, createdDID2.DID.ID: true}
				for _, id := range gotDIDsResponse.DIDs {
					if _, ok := knownDIDs[id.ID]; !ok {
						tt.Error("got unknown DID")
					} else {
						delete(knownDIDs, id.ID)
					}
				}
				assert.Len(tt, knownDIDs, 0)
			})

			t.Run("Test Resolve DIDs", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				_, keyStore, _ := testKeyStore(tt, db)
				didService, _ := testDIDRouter(tt, db, keyStore, []string{"key", "web"}, nil)

				// bad resolution request
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/resolver/bad", nil)
				w := httptest.NewRecorder()

				badParams := map[string]string{"id": "bad"}
				c := newRequestContextWithParams(w, req, badParams)
				didService.ResolveDID(c)
				assert.Contains(tt, w.Body.String(), "malformed did")

				w = httptest.NewRecorder()

				// known method, bad did
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/resolver/did:key:abcd", nil)
				badParams = map[string]string{
					"id": "did:key:abcd",
				}
				c = newRequestContextWithParams(w, req, badParams)
				didService.ResolveDID(c)
				assert.Contains(tt, w.Body.String(), "unable to resolve DID did:key:abcd")

				w = httptest.NewRecorder()

				// known method, good did
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/resolver/did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", nil)
				goodParams := map[string]string{
					"id": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
				}
				c = newRequestContextWithParams(w, req, goodParams)
				didService.ResolveDID(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resolutionResponse router.ResolveDIDResponse
				err := json.NewDecoder(w.Body).Decode(&resolutionResponse)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, resolutionResponse.DIDDocument)
				assert.Equal(tt, "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", resolutionResponse.DIDDocument.ID)
			})
		})
	}
}

func TestBatchCreateDIDs(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			db := test.ServiceStorage(t)
			require.NotEmpty(t, db)
			_, keyStoreService, factory := testKeyStore(t, db)

			createDIDRequest := router.BatchCreateDIDsRequest{
				Requests: []router.CreateDIDByMethodRequest{
					{
						KeyType: crypto.Ed25519,
					},
					{
						KeyType: crypto.Ed25519,
					},
					{
						KeyType: crypto.Ed25519,
					},
				},
			}

			_, batchDIDRouter := testDIDRouter(t, db, keyStoreService, []string{"key"}, factory)
			t.Run(" Batch Create DID By Method: Key", func(tt *testing.T) {
				w := httptest.NewRecorder()
				requestReader := newRequestValue(tt, createDIDRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
				params := map[string]string{"method": "key"}
				c := newRequestContextWithParams(w, req, params)

				batchDIDRouter.BatchCreateDIDs(c)

				assert.True(tt, util.Is2xxResponse(w.Code))
				var resp router.BatchCreateDIDsResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.Len(tt, resp.DIDs, 3)
			})

			t.Run("Fails with malformed request", func(ttt *testing.T) {
				createDIDRequest := createDIDRequest
				// missing the data field
				createDIDRequest.Requests = append(createDIDRequest.Requests, router.CreateDIDByMethodRequest{
					KeyType: "bad",
				})

				requestValue := newRequestValue(ttt, createDIDRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key/batch", requestValue)
				w := httptest.NewRecorder()
				params := map[string]string{"method": "key"}
				c := newRequestContextWithParams(w, req, params)
				batchDIDRouter.BatchCreateDIDs(c)
				assert.Equal(ttt, http.StatusInternalServerError, w.Code)
				assert.Contains(ttt, w.Body.String(), "unsupported did:key type: bad")
			})

			t.Run("Fails with more than 1000 requests", func(ttt *testing.T) {
				createDIDRequest := createDIDRequest
				// missing the data field
				for i := 0; i < 1000; i++ {
					createDIDRequest.Requests = append(createDIDRequest.Requests, createDIDRequest.Requests[0])
				}

				requestValue := newRequestValue(ttt, createDIDRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key/batch", requestValue)
				w := httptest.NewRecorder()
				params := map[string]string{"method": "key"}
				c := newRequestContextWithParams(w, req, params)
				batchDIDRouter.BatchCreateDIDs(c)
				assert.Equal(ttt, http.StatusBadRequest, w.Code)
				assert.Contains(ttt, w.Body.String(), "max number of requests is 100")
			})
		})
	}
}

func createDIDWithRouter(tt *testing.T, didService *router.DIDRouter) {
	w := httptest.NewRecorder()
	createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
	requestReader := newRequestValue(tt, createDIDRequest)
	params := map[string]string{"method": "key"}
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)

	c := newRequestContextWithParams(w, req, params)
	didService.CreateDIDByMethod(c)
	assert.True(tt, util.Is2xxResponse(w.Code))

	var createdDID router.CreateDIDByMethodResponse
	err := json.NewDecoder(w.Body).Decode(&createdDID)
	assert.NoError(tt, err)
}
