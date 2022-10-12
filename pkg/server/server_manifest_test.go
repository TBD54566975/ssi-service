package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestManifestAPI(t *testing.T) {
	t.Run("Test Create Manifest", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)

		// missing required field: Manifest
		badManifestRequest := router.CreateManifestRequest{}

		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", badRequestValue)
		w := httptest.NewRecorder()

		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create manifest request")

		// reset the http recorder
		w.Flush()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.Manifest)
		assert.Equal(tt, resp.Manifest.Issuer.ID, issuerDID.DID.ID)
	})

	t.Run("Test Get Manifest By ID", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)

		w := httptest.NewRecorder()

		// get a manifest that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
		err = manifestRouter.GetManifest(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get manifest without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get a manifest with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
		err = manifestRouter.GetManifest(newRequestContextWithParams(map[string]string{"id": "bad"}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get manifest with id: bad")

		// reset recorder between calls
		w.Flush()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get manifest by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestRouter.GetManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.NoError(tt, err)

		var getManifestResp router.GetManifestResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestResp)
		assert.Equal(tt, resp.Manifest.ID, getManifestResp.ID)
	})

	t.Run("Test Get Manifests", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)

		w := httptest.NewRecorder()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get manifest by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests"), nil)
		err = manifestRouter.GetManifests(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getManifestsResp router.GetManifestsResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestsResp)
		assert.Len(tt, getManifestsResp.Manifests, 1)
		assert.Equal(tt, resp.Manifest.ID, getManifestsResp.Manifests[0].ID)
	})

	t.Run("Test Delete Manifest", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		w := httptest.NewRecorder()
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w.Flush()

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestRouter.GetManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.NoError(tt, err)

		var getManifestResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestResp)
		assert.Equal(tt, resp.Manifest.ID, getManifestResp.ID)

		w.Flush()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestRouter.DeleteManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestRouter.GetManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get manifest with id: %s", resp.Manifest.ID))
	})

	t.Run("Test Submit Application", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)

		// missing required field: Application
		badManifestRequest := router.SubmitApplicationRequest{
			ApplicantDID: "did:example:abcd",
		}

		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", badRequestValue)
		w := httptest.NewRecorder()

		err = manifestRouter.SubmitApplication(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid submit application request")

		// reset the http recorder
		w.Flush()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		applicantDID := "did:example:abcd"

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.Manifest)
		assert.Equal(tt, resp.Manifest.Issuer.ID, issuerDID.DID.ID)

		// good application request
		createApplicationRequest := getValidApplicationRequest(applicantDID, resp.Manifest.ID, resp.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		applicationRequestValue := newRequestValue(tt, createApplicationRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestRouter.SubmitApplication(newRequestContext(), w, req)

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, appResp.Response)
		assert.Equal(tt, appResp.Response.ManifestID, resp.Manifest.ID)

	})

	t.Run("Test Get Application By ID and Get Applications", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)
		w := httptest.NewRecorder()

		// get a application that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications/bad", nil)
		err = manifestRouter.GetApplication(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get application without ID parameter")

		// reset recorder between calls
		w.Flush()

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		applicantDID := "did:example:abcd"

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// good application request
		createApplicationRequest := getValidApplicationRequest(applicantDID, resp.Manifest.ID, resp.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		applicationRequestValue := newRequestValue(tt, createApplicationRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestRouter.SubmitApplication(newRequestContext(), w, req)

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		// get response by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/responses/%s", appResp.Response.ID), nil)
		err = manifestRouter.GetResponse(newRequestContextWithParams(map[string]string{"id": appResp.Response.ID}), w, req)
		assert.NoError(tt, err)

		var getResponseResponse router.GetResponseResponse
		err = json.NewDecoder(w.Body).Decode(&getResponseResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getResponseResponse)
		assert.Equal(tt, appResp.Response.ID, getResponseResponse.Response.ID)

		// get all responses
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/responses", nil)
		err = manifestRouter.GetResponses(newRequestContext(), w, req)

		var getResponsesResp router.GetResponsesResponse
		err = json.NewDecoder(w.Body).Decode(&getResponsesResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getResponsesResp)

		assert.Len(tt, getResponsesResp.Responses, 1)

		// get all applications
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestRouter.GetApplications(newRequestContext(), w, req)

		var getApplicationsResp router.GetApplicationsResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationsResp)

		assert.Len(tt, getApplicationsResp.Applications, 1)

		// get application by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
		err = manifestRouter.GetApplication(newRequestContextWithParams(map[string]string{"id": getApplicationsResp.Applications[0].ID}), w, req)
		assert.NoError(tt, err)

		var getApplicationResponse router.GetApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationResponse)
		assert.Equal(tt, getApplicationsResp.Applications[0].ID, getApplicationResponse.ID)
	})

	t.Run("Test Delete Application", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credentialService := testCredentialService(tt, bolt, keyStoreService, didService, schemaService)
		manifestRouter, _ := testManifest(tt, bolt, keyStoreService, credentialService)

		// create an issuer
		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		applicantDID := "did:example:abcd"

		// create a schema for the creds to be issued against
		licenseSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"licenseType": map[string]interface{}{
					"type": "string",
				},
			},
			"additionalProperties": true,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: issuerDID.DID.ID, Name: "license schema", Schema: licenseSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// good request
		createManifestRequest := getValidManifestRequest(issuerDID.DID.ID, createdSchema.ID)

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		w := httptest.NewRecorder()
		err = manifestRouter.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// good application request
		createApplicationRequest := getValidApplicationRequest(applicantDID, resp.Manifest.ID, resp.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		applicationRequestValue := newRequestValue(tt, createApplicationRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestRouter.SubmitApplication(newRequestContext(), w, req)

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		// get all applications
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestRouter.GetApplications(newRequestContext(), w, req)

		var getApplicationsResp router.GetApplicationsResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationsResp)

		assert.Len(tt, getApplicationsResp.Applications, 1)

		// get the application
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
		err = manifestRouter.GetApplication(newRequestContextWithParams(map[string]string{"id": getApplicationsResp.Applications[0].ID}), w, req)
		assert.NoError(tt, err)

		var getApplicationResp router.GetApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationResp)
		assert.Equal(tt, resp.Manifest.ID, getApplicationResp.Application.ManifestID)

		// delete the application
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationResp.Application.ID), nil)
		err = manifestRouter.DeleteApplication(newRequestContextWithParams(map[string]string{"id": getApplicationResp.Application.ID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", appResp.Response.ID), nil)
		err = manifestRouter.GetApplication(newRequestContextWithParams(map[string]string{"id": appResp.Response.ID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get application with id: %s", appResp.Response.ID))
	})
}
