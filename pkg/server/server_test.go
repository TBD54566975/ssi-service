package server

import (
	"bytes"
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/tbd54566975/ssi-service/pkg/service/dwn"

	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestHealthCheckAPI(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("")
	assert.NoError(t, err)
	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/health", nil)
	w := httptest.NewRecorder()

	err = router.Health(context.TODO(), w, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var resp router.GetHealthCheckResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.Equal(t, router.HealthOK, resp.Status)

}

func TestReadinessAPI(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("")
	assert.NoError(t, err)

	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/readiness", nil)
	w := httptest.NewRecorder()

	handler := router.Readiness(nil)
	err = handler(newRequestContext(), w, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var resp router.GetReadinessResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.Equal(t, svcframework.StatusReady, resp.Status.Status)
	assert.Len(t, resp.ServiceStatuses, 0)
}

func TestDIDAPI(t *testing.T) {
	t.Run("Test Get DID Methods", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		didService := newDIDService(tt, bolt)

		// get DID methods
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids", nil)
		w := httptest.NewRecorder()

		err = didService.GetDIDMethods(newRequestContext(), w, req)
		assert.NoError(tt, err)
		assert.Equal(tt, http.StatusOK, w.Result().StatusCode)

		var resp router.GetDIDMethodsResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Len(tt, resp.DIDMethods, 1)
		assert.Equal(tt, resp.DIDMethods[0], did.KeyMethod)
	})

	t.Run("Test Create DID By Method: Key", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		didService := newDIDService(tt, bolt)

		// create DID by method - key - missing body
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", nil)
		w := httptest.NewRecorder()
		params := map[string]string{
			"method": "key",
		}

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create DID request")

		// with body, bad key type
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: "bad"}
		requestReader := newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
		w = httptest.NewRecorder()

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create DID for method<key> with key type: bad")

		// with body, good key type
		createDIDRequest = router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
		w = httptest.NewRecorder()

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var resp router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Contains(tt, resp.DID.ID, did.KeyMethod)
	})

	t.Run("Test Get DID By Method", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		didService := newDIDService(tt, bolt)

		// get DID by method
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/bad/worse", nil)
		w := httptest.NewRecorder()

		// bad params
		badParams := map[string]string{
			"method": "bad",
			"id":     "worse",
		}
		err = didService.GetDIDByMethod(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get DID for method<bad>")

		// good method, bad id
		badParams1 := map[string]string{
			"method": "key",
			"id":     "worse",
		}
		err = didService.GetDIDByMethod(newRequestContextWithParams(badParams1), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get DID for method<key> with id: worse")

		// store a DID
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		params := map[string]string{"method": "key"}
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
		w = httptest.NewRecorder()

		err = didService.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var createdDID router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&createdDID)
		assert.NoError(tt, err)

		// get it back
		createdID := createdDID.DID.ID
		getDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
		req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)
		w = httptest.NewRecorder()

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
}

func newDIDService(t *testing.T, bolt *storage.BoltDB) *router.DIDRouter {
	serviceConfig := config.DIDServiceConfig{Methods: []string{string(did.KeyMethod)}}
	didService, err := did.NewDIDService(serviceConfig, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, didService)

	// create router for service
	didRouter, err := router.NewDIDRouter(didService)
	require.NoError(t, err)
	require.NotEmpty(t, didRouter)

	return didRouter
}

func TestSchemaAPI(t *testing.T) {
	t.Run("Test Create Schema", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		schemaService := newSchemaService(tt, bolt)

		simpleSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"foo": map[string]interface{}{
					"type": "string",
				},
			},
			"required":             []interface{}{"foo"},
			"additionalProperties": false,
		}
		badSchemaRequest := router.CreateSchemaRequest{Schema: simpleSchema}
		schemaRequestValue := newRequestValue(tt, badSchemaRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
		w := httptest.NewRecorder()

		err = schemaService.CreateSchema(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create schema request")

		// reset the http recorder
		w.Flush()

		schemaRequest := router.CreateSchemaRequest{Author: "did:test", Name: "test schema", Schema: simpleSchema}
		schemaRequestValue = newRequestValue(tt, schemaRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
		err = schemaService.CreateSchema(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateSchemaResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.ID)
		assert.EqualValues(tt, schemaRequest.Schema, resp.Schema.Schema)
	})

	t.Run("Test Get Schemas", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		schemaService := newSchemaService(tt, bolt)

		// get schema that doesn't exist
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas/bad", nil)
		err = schemaService.GetSchema(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get schema without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get schema with invalid id
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas/bad", nil)
		err = schemaService.GetSchema(newRequestContextWithParams(map[string]string{"id": "bad"}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get schema with id: bad")

		// reset recorder between calls
		w.Flush()

		// get all schemas - get none
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas", nil)
		err = schemaService.GetSchemas(newRequestContext(), w, req)
		assert.NoError(tt, err)
		var getSchemasResp router.GetSchemasResponse
		err = json.NewDecoder(w.Body).Decode(&getSchemasResp)
		assert.NoError(tt, err)
		assert.Len(tt, getSchemasResp.Schemas, 0)

		// reset recorder between calls
		w.Flush()

		// create a schema
		simpleSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"foo": map[string]interface{}{
					"type": "string",
				},
			},
			"required":             []interface{}{"foo"},
			"additionalProperties": false,
		}
		schemaRequest := router.CreateSchemaRequest{Author: "did:test", Name: "test schema", Schema: simpleSchema}
		schemaRequestValue := newRequestValue(tt, schemaRequest)
		createReq := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)

		err = schemaService.CreateSchema(newRequestContext(), w, createReq)
		assert.NoError(tt, err)

		var createResp router.CreateSchemaResponse
		err = json.NewDecoder(w.Body).Decode(&createResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, createResp.ID)
		assert.EqualValues(tt, schemaRequest.Schema, createResp.Schema.Schema)

		// reset recorder between calls
		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", createResp.ID), nil)
		err = schemaService.GetSchema(newRequestContextWithParams(map[string]string{"id": createResp.ID}), w, req)
		assert.NoError(tt, err)

		var gotSchemaResp router.GetSchemaResponse
		err = json.NewDecoder(w.Body).Decode(&gotSchemaResp)
		assert.NoError(tt, err)

		assert.Equal(tt, createResp.ID, gotSchemaResp.Schema.ID)
		assert.Equal(tt, createResp.Schema.Schema, gotSchemaResp.Schema.Schema)

		// reset recorder between calls
		w.Flush()

		// get all schemas - get none
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas", nil)
		err = schemaService.GetSchemas(newRequestContext(), w, req)
		assert.NoError(tt, err)
		err = json.NewDecoder(w.Body).Decode(&getSchemasResp)
		assert.NoError(tt, err)
		assert.Len(tt, getSchemasResp.Schemas, 1)
	})
}

func newSchemaService(t *testing.T, bolt *storage.BoltDB) *router.SchemaRouter {
	schemaService, err := schema.NewSchemaService(config.SchemaServiceConfig{}, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, schemaService)

	// create router for service
	schemaRouter, err := router.NewSchemaRouter(schemaService)
	require.NoError(t, err)
	require.NotEmpty(t, schemaRouter)

	return schemaRouter
}

func TestCredentialAPI(t *testing.T) {
	t.Run("Test Create Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		credService := newCredentialService(tt, bolt)

		// missing required field: data
		badCredRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: "did:abc:456",
			Expiry:  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		badRequestValue := newRequestValue(tt, badCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", badRequestValue)
		w := httptest.NewRecorder()

		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create credential request")

		// reset the http recorder
		w.Flush()

		// good request
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.Credential)
		assert.Equal(tt, resp.Credential.Issuer, "did:abc:123")
	})

	t.Run("Test Get Credential By ID", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		credService := newCredentialService(tt, bolt)

		w := httptest.NewRecorder()

		// get a cred that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		err = credService.GetCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get credential without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get a cred with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": "bad"}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get credential with id: bad")

		// reset recorder between calls
		w.Flush()

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", resp.Credential.ID), nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.NoError(tt, err)

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.Equal(tt, resp.Credential.ID, getCredResp.ID)
	})

	t.Run("Test Get Credential By Schema", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		credService := newCredentialService(tt, bolt)

		w := httptest.NewRecorder()

		schemaID := "https://test-schema.com/name"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: "did:abc:456",
			Schema:  schemaID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w.Flush()

		// get credential by schema
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", schemaID), nil)
		err = credService.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].CredentialSchema.ID)
	})

	t.Run("Test Get Credential By Issuer", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		credService := newCredentialService(tt, bolt)

		w := httptest.NewRecorder()

		issuerID := "did:abc:123"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w.Flush()

		// get credential by issuer id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?issuer=%s", issuerID), nil)
		err = credService.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.Issuer, getCredsResp.Credentials[0].Issuer)
	})

	t.Run("Test Get Credential By Subject", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		credService := newCredentialService(tt, bolt)

		w := httptest.NewRecorder()

		subjectID := "did:abc:456"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: subjectID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get credential by subject id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?subject=%s", subjectID), nil)
		err = credService.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty], getCredsResp.Credentials[0].CredentialSubject[credsdk.VerifiableCredentialIDProperty])
	})

	t.Run("Test Delete Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		credService := newCredentialService(tt, bolt)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		w := httptest.NewRecorder()
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w.Flush()

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", resp.Credential.ID), nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.NoError(tt, err)

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.Equal(tt, resp.Credential.ID, getCredResp.ID)

		w.Flush()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", resp.Credential.ID), nil)
		err = credService.DeleteCredential(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", resp.Credential.ID), nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get credential with id: %s", resp.Credential.ID))
	})
}

func newCredentialService(t *testing.T, bolt *storage.BoltDB) *router.CredentialRouter {
	credentialService, err := credential.NewCredentialService(config.CredentialServiceConfig{}, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, credentialService)

	// create router for service
	credentialRouter, err := router.NewCredentialRouter(credentialService)
	require.NoError(t, err)
	require.NotEmpty(t, credentialRouter)

	return credentialRouter
}

func TestManifestAPI(t *testing.T) {
	t.Run("Test Create Manifest", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		// missing required field: Manifest
		badManifestRequest := router.CreateManifestRequest{}

		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", badRequestValue)
		w := httptest.NewRecorder()

		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create manifest request")

		// reset the http recorder
		w.Flush()

		// good request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.Manifest)
		assert.Equal(tt, resp.Manifest.Issuer.ID, "did:abc:123")
	})

	t.Run("Test Get Manifest By ID", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		w := httptest.NewRecorder()

		// get a manifest that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
		err = manifestService.GetManifest(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get manifest without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get a manifest with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/bad", nil)
		err = manifestService.GetManifest(newRequestContextWithParams(map[string]string{"id": "bad"}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get manifest with id: bad")

		// reset recorder between calls
		w.Flush()

		// good request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get manifest by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestService.GetManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.NoError(tt, err)

		var getManifestResp router.GetManifestResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestResp)
		assert.Equal(tt, resp.Manifest.ID, getManifestResp.ID)
	})

	t.Run("Test Get Manifests", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		w := httptest.NewRecorder()

		// good request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// get manifest by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests"), nil)
		err = manifestService.GetManifests(newRequestContext(), w, req)
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

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		// good request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		w := httptest.NewRecorder()
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w.Flush()

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestService.GetManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.NoError(tt, err)

		var getManifestResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getManifestResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getManifestResp)
		assert.Equal(tt, resp.Manifest.ID, getManifestResp.ID)

		w.Flush()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestService.DeleteManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/%s", resp.Manifest.ID), nil)
		err = manifestService.GetManifest(newRequestContextWithParams(map[string]string{"id": resp.Manifest.ID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get manifest with id: %s", resp.Manifest.ID))
	})

	t.Run("Test Submit Application", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		// missing required field: Application
		badManifestRequest := router.SubmitApplicationRequest{
			RequesterDID: "id123",
		}

		badRequestValue := newRequestValue(tt, badManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", badRequestValue)
		w := httptest.NewRecorder()

		err = manifestService.SubmitApplication(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid submit application request")

		// reset the http recorder
		w.Flush()

		// good request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.Manifest)
		assert.Equal(tt, resp.Manifest.Issuer.ID, "did:abc:123")

		// good application request
		createApplicationRequest := getValidApplicationRequest(resp.Manifest.ID, resp.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		applicationRequestValue := newRequestValue(tt, createApplicationRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestService.SubmitApplication(newRequestContext(), w, req)

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, appResp.Response)
		assert.Equal(tt, appResp.Response.ManifestID, resp.Manifest.ID)

	})

	t.Run("Test Get Application By ID and Get Applications", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		w := httptest.NewRecorder()

		// get a application that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications/bad", nil)
		err = manifestService.GetApplication(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get application without ID parameter")

		// reset recorder between calls
		w.Flush()

		// good manifest request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// good application request
		createApplicationRequest := getValidApplicationRequest(resp.Manifest.ID, resp.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		applicationRequestValue := newRequestValue(tt, createApplicationRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestService.SubmitApplication(newRequestContext(), w, req)

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		// get response by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/responses/%s", appResp.Response.ID), nil)
		err = manifestService.GetResponse(newRequestContextWithParams(map[string]string{"id": appResp.Response.ID}), w, req)
		assert.NoError(tt, err)

		var getResponseResponse router.GetResponseResponse
		err = json.NewDecoder(w.Body).Decode(&getResponseResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getResponseResponse)
		assert.Equal(tt, appResp.Response.ID, getResponseResponse.Response.ID)

		// get all responses
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/responses", nil)
		err = manifestService.GetResponses(newRequestContext(), w, req)

		var getResponsesResp router.GetResponsesResponse
		err = json.NewDecoder(w.Body).Decode(&getResponsesResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getResponsesResp)

		assert.Len(tt, getResponsesResp.Responses, 1)

		// get all applications
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestService.GetApplications(newRequestContext(), w, req)

		var getApplicationsResp router.GetApplicationsResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationsResp)

		assert.Len(tt, getApplicationsResp.Applications, 1)

		// get application by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
		err = manifestService.GetApplication(newRequestContextWithParams(map[string]string{"id": getApplicationsResp.Applications[0].ID}), w, req)
		assert.NoError(tt, err)

		var getApplicationResponse router.GetApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationResponse)
		assert.Equal(tt, getApplicationsResp.Applications[0].ID, getApplicationResponse.ID)
	})

	t.Run("Test Delete Application", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		manifestService := newManifestService(tt, bolt)

		// good manifest request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		w := httptest.NewRecorder()
		err = manifestService.CreateManifest(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateManifestResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// good application request
		createApplicationRequest := getValidApplicationRequest(resp.Manifest.ID, resp.Manifest.PresentationDefinition.InputDescriptors[0].ID)

		applicationRequestValue := newRequestValue(tt, createApplicationRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestService.SubmitApplication(newRequestContext(), w, req)

		var appResp router.SubmitApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&appResp)
		assert.NoError(tt, err)

		// get all applications
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/manifests/applications", applicationRequestValue)
		err = manifestService.GetApplications(newRequestContext(), w, req)

		var getApplicationsResp router.GetApplicationsResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationsResp)

		assert.Len(tt, getApplicationsResp.Applications, 1)

		// get the application
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationsResp.Applications[0].ID), nil)
		err = manifestService.GetApplication(newRequestContextWithParams(map[string]string{"id": getApplicationsResp.Applications[0].ID}), w, req)
		assert.NoError(tt, err)

		var getApplicationResp router.GetApplicationResponse
		err = json.NewDecoder(w.Body).Decode(&getApplicationResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getApplicationResp)
		assert.Equal(tt, resp.Manifest.ID, getApplicationResp.Application.ManifestID)

		// delete the application
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", getApplicationResp.Application.ID), nil)
		err = manifestService.DeleteApplication(newRequestContextWithParams(map[string]string{"id": getApplicationResp.Application.ID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/manifests/applications/%s", appResp.Response.ID), nil)
		err = manifestService.GetApplication(newRequestContextWithParams(map[string]string{"id": appResp.Response.ID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get application with id: %s", appResp.Response.ID))
	})
}

func newManifestService(t *testing.T, bolt *storage.BoltDB) *router.ManifestRouter {
	manifestService, err := manifest.NewManifestService(config.ManifestServiceConfig{}, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, manifestService)

	// create router for service
	manifestRouter, err := router.NewManifestRouter(manifestService)
	require.NoError(t, err)
	require.NotEmpty(t, manifestRouter)

	return manifestRouter
}

func TestDWNAPI(t *testing.T) {
	t.Run("Test DWN Publish Manifest", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		dwnService := newDWNService(tt, bolt)

		manifestService := newManifestService(tt, bolt)

		w := httptest.NewRecorder()

		// good request
		createManifestRequest := getValidManifestRequest()

		requestValue := newRequestValue(tt, createManifestRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/manifests", requestValue)
		err = manifestService.CreateManifest(newRequestContext(), w, req)
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
func newDWNService(t *testing.T, bolt *storage.BoltDB) *router.DWNRouter {
	dwnService, err := dwn.NewDWNService(config.DWNServiceConfig{DWNEndpoint: "test-endpoint"}, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, dwnService)

	// create router for service
	dwnRouter, err := router.NewDWNRouter(dwnService)
	require.NoError(t, err)
	require.NotEmpty(t, dwnRouter)

	return dwnRouter
}

func TestKeyStoreAPI(t *testing.T) {
	t.Run("Test Store Key", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := newKeyStoreService(tt, bolt)
		w := httptest.NewRecorder()

		// bad key type
		badKeyStoreRequest := router.StoreKeyRequest{
			ID:               "test-kid",
			Type:             "bad",
			Controller:       "me",
			Base58PrivateKey: "bad",
		}
		badRequestValue := newRequestValue(tt, badKeyStoreRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", badRequestValue)
		err = keyStoreService.StoreKey(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not store key: test-kid, unsupported key type: bad")

		// reset the http recorder
		w.Flush()

		// store a valid key
		_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)

		privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
		assert.NoError(tt, err)

		// good request
		storeKeyRequest := router.StoreKeyRequest{
			ID:               "did:test:me#key-1",
			Type:             crypto.Ed25519,
			Controller:       "did:test:me",
			Base58PrivateKey: base58.Encode(privKeyBytes),
		}
		requestValue := newRequestValue(tt, storeKeyRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
		err = keyStoreService.StoreKey(newRequestContext(), w, req)
		assert.NoError(tt, err)
	})

	t.Run("Test Get Key Details", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := newKeyStoreService(tt, bolt)
		w := httptest.NewRecorder()

		// store a valid key
		_, privKey, err := crypto.GenerateKeyByKeyType(crypto.Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKey)

		privKeyBytes, err := crypto.PrivKeyToBytes(privKey)
		assert.NoError(tt, err)

		// good request
		keyID := "did:test:me#key-2"
		controller := "did:test:me"
		storeKeyRequest := router.StoreKeyRequest{
			ID:               keyID,
			Type:             crypto.Ed25519,
			Controller:       controller,
			Base58PrivateKey: base58.Encode(privKeyBytes),
		}
		requestValue := newRequestValue(tt, storeKeyRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/keys", requestValue)
		err = keyStoreService.StoreKey(newRequestContext(), w, req)
		assert.NoError(tt, err)

		// get it back
		getRecorder := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/keys/%s", keyID), nil)
		err = keyStoreService.GetKeyDetails(newRequestContextWithParams(map[string]string{"id": keyID}), getRecorder, getReq)
		assert.NoError(tt, err)

		var resp router.GetKeyDetailsResponse
		err = json.NewDecoder(getRecorder.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Equal(tt, keyID, resp.ID)
		assert.Equal(tt, controller, resp.Controller)
		assert.Equal(tt, crypto.Ed25519, resp.Type)
	})
}

func newKeyStoreService(t *testing.T, bolt *storage.BoltDB) *router.KeyStoreRouter {
	serviceConfig := config.KeyStoreServiceConfig{ServiceKeyPassword: "test-password"}
	keyStoreService, err := keystore.NewKeyStoreService(serviceConfig, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, keyStoreService)

	// create router for service
	keyStoreRouter, err := router.NewKeyStoreRouter(keyStoreService)
	require.NoError(t, err)
	require.NotEmpty(t, keyStoreRouter)

	return keyStoreRouter
}

func newRequestValue(t *testing.T, data interface{}) io.Reader {
	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)
	require.NotEmpty(t, dataBytes)
	return bytes.NewReader(dataBytes)
}

// construct a context value as expected by our handler
func newRequestContext() context.Context {
	return context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
}

// as required by https://github.com/dimfeld/httptreemux's context handler
func newRequestContextWithParams(params map[string]string) context.Context {
	ctx := context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
	return httptreemux.AddParamsToContext(ctx, params)
}

func getValidManifestRequest() manifest.CreateManifestRequest {
	createManifestRequest := manifest.CreateManifestRequest{
		Manifest: manifestsdk.CredentialManifest{
			ID:          "WA-DL-CLASS-A",
			SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
			Issuer: manifestsdk.Issuer{
				ID: "did:abc:123",
			},
			PresentationDefinition: &exchange.PresentationDefinition{
				ID: "pres-def-id",
				InputDescriptors: []exchange.InputDescriptor{
					{
						ID: "test-id",
						Constraints: &exchange.Constraints{
							Fields: []exchange.Field{
								{
									Path: []string{".vc.id"},
								},
							},
						},
					},
				},
			},
			OutputDescriptors: []manifestsdk.OutputDescriptor{
				{
					ID:          "id1",
					Schema:      "https://test.com/schema",
					Name:        "good ID",
					Description: "it's all good",
				},
				{
					ID:          "id2",
					Schema:      "https://test.com/schema",
					Name:        "good ID",
					Description: "it's all good",
				},
			},
		},
	}

	return createManifestRequest
}

func getValidApplicationRequest(manifestID string, submissionDescriptorId string) manifest.SubmitApplicationRequest {

	createApplication := manifestsdk.CredentialApplication{
		ID:          uuid.New().String(),
		SpecVersion: "https://identity.foundation/credential-manifest/spec/v1.0.0/",
		ManifestID:  manifestID,
		Format: &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
		PresentationSubmission: &exchange.PresentationSubmission{
			ID:           "psid",
			DefinitionID: "definitionId",
			DescriptorMap: []exchange.SubmissionDescriptor{
				{
					ID:     submissionDescriptorId,
					Format: "jwt",
					Path:   "path",
				},
			},
		},
	}

	createApplicationRequest := manifest.SubmitApplicationRequest{
		Application:  createApplication,
		RequesterDID: "did:user:123",
	}

	return createApplicationRequest
}
