package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestSchemaAPI(t *testing.T) {
	t.Run("Test Create Schema", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		schemaService := testSchemaRouter(tt, bolt, keyStoreService)

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
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		schemaService := testSchemaRouter(tt, bolt, keyStoreService)

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
