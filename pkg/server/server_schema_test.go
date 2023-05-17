package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
)

func TestSchemaAPI(t *testing.T) {
	t.Run("Test Create SchemaID", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

		simpleSchema := getTestSchema()
		badSchemaRequest := router.CreateSchemaRequest{Schema: simpleSchema}
		schemaRequestValue := newRequestValue(tt, badSchemaRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := schemaService.CreateSchema(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create schema request")

		// reset the http recorder
		w.Flush()

		schemaRequest := router.CreateSchemaRequest{Author: "did:test", Name: "test schema", Schema: simpleSchema}
		schemaRequestValue = newRequestValue(tt, schemaRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)

		newRequestContext(w, req)
		err = schemaService.CreateSchema(c)
		assert.NoError(tt, err)

		var resp router.CreateSchemaResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.ID)
		assert.EqualValues(tt, schemaRequest.Schema, resp.Schema.Schema)
	})

	t.Run("Test Sign & Verify SchemaID", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

		w := httptest.NewRecorder()

		// sign request with unknown DID
		simpleSchema := getTestSchema()
		schemaRequest := router.CreateSchemaRequest{Author: "did:test", Name: "test schema", Schema: simpleSchema, Sign: true}
		schemaRequestValue := newRequestValue(tt, schemaRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
		c := newRequestContext(w, req)
		err := schemaService.CreateSchema(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot sign schema without authorKID")

		// create a DID
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// sign with known DID
		kid := issuerDID.DID.VerificationMethod[0].ID
		schemaRequest = router.CreateSchemaRequest{Author: issuerDID.DID.ID, AuthorKID: kid, Name: "test schema", Schema: simpleSchema, Sign: true}
		schemaRequestValue = newRequestValue(tt, schemaRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
		c = newRequestContext(w, req)
		err = schemaService.CreateSchema(c)
		assert.NoError(tt, err)

		var resp router.CreateSchemaResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.SchemaJWT)
		assert.NotEmpty(tt, resp.ID)
		assert.EqualValues(tt, schemaRequest.Schema, resp.Schema.Schema)

		// verify schema
		verifySchemaRequest := router.VerifySchemaRequest{SchemaJWT: *resp.SchemaJWT}
		verifySchemaRequestValue := newRequestValue(tt, verifySchemaRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas/verification", verifySchemaRequestValue)
		c = newRequestContext(w, req)
		err = schemaService.VerifySchema(c)
		assert.NoError(tt, err)

		var verifyResp router.VerifySchemaResponse
		err = json.NewDecoder(w.Body).Decode(&verifyResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifyResp)
		assert.True(tt, verifyResp.Verified)

		// verify a bad schema
		verifySchemaRequest = router.VerifySchemaRequest{SchemaJWT: "bad"}
		verifySchemaRequestValue = newRequestValue(tt, verifySchemaRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas/verification", verifySchemaRequestValue)
		c = newRequestContext(w, req)
		err = schemaService.VerifySchema(c)
		assert.NoError(tt, err)

		err = json.NewDecoder(w.Body).Decode(&verifyResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifyResp)
		assert.False(tt, verifyResp.Verified)
		assert.Contains(tt, verifyResp.Reason, "could not verify schema")
	})

	t.Run("Test Get SchemaID and Get Schemas", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

		// get schema that doesn't exist
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas/bad", nil)
		c := newRequestContext(w, req)
		err := schemaService.GetSchema(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get schema without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get schema with invalid id
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas/bad", nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
		err = schemaService.GetSchema(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get schema with id: bad")

		// reset recorder between calls
		w.Flush()

		// get all schemas - get none
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas", nil)
		c = newRequestContext(w, req)
		err = schemaService.GetSchemas(c)
		assert.NoError(tt, err)
		var getSchemasResp router.GetSchemasResponse
		err = json.NewDecoder(w.Body).Decode(&getSchemasResp)
		assert.NoError(tt, err)
		assert.Len(tt, getSchemasResp.Schemas, 0)

		// reset recorder between calls
		w.Flush()

		// create a schema
		simpleSchema := getTestSchema()

		schemaRequest := router.CreateSchemaRequest{Author: "did:test", Name: "test schema", Schema: simpleSchema}
		schemaRequestValue := newRequestValue(tt, schemaRequest)
		createReq := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)

		c = newRequestContext(w, createReq)
		err = schemaService.CreateSchema(c)
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
		c = newRequestContextWithParams(w, req, map[string]string{"id": createResp.ID})
		err = schemaService.GetSchema(c)
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
		c = newRequestContext(w, req)
		err = schemaService.GetSchemas(c)
		assert.NoError(tt, err)
		err = json.NewDecoder(w.Body).Decode(&getSchemasResp)
		assert.NoError(tt, err)
		assert.Len(tt, getSchemasResp.Schemas, 1)
	})

	t.Run("Test Delete SchemaID", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

		w := httptest.NewRecorder()

		// delete a schema that doesn't exist
		req := httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/schemas/bad", nil)
		c := newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
		err := schemaService.DeleteSchema(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not delete schema with id: bad")

		// create a schema
		simpleSchema := getTestSchema()

		schemaRequest := router.CreateSchemaRequest{Author: "did:test", Name: "test schema", Schema: simpleSchema}
		schemaRequestValue := newRequestValue(tt, schemaRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
		c = newRequestContext(w, req)
		err = schemaService.CreateSchema(c)
		assert.NoError(tt, err)

		var resp router.CreateSchemaResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.ID)
		assert.EqualValues(tt, schemaRequest.Schema, resp.Schema.Schema)

		w.Flush()

		// get schema by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", resp.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.ID})
		err = schemaService.GetSchema(c)
		assert.NoError(tt, err)

		w.Flush()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", resp.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.ID})
		err = schemaService.DeleteSchema(c)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", resp.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": resp.ID})
		err = schemaService.GetSchema(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "schema not found")
	})
}

func getTestSchema() schema.JSONSchema {
	return map[string]any{
		"$id":         "https://example.com/foo.schema.json",
		"$schema":     "http://json-schema.org/draft-07/schema#",
		"description": "foo schema",
		"type":        "object",
		"properties": map[string]any{
			"foo": map[string]any{
				"type": "string",
			},
		},
		"required":             []any{"foo"},
		"additionalProperties": false,
	}
}
