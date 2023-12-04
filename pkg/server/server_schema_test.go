package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestSchemaAPI(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Test Create JsonSchema Schema", func(tt *testing.T) {
				bolt := test.ServiceStorage(tt)
				require.NotEmpty(tt, bolt)

				keyStoreService, _ := testKeyStoreService(tt, bolt)
				didService, _ := testDIDService(tt, bolt, keyStoreService, nil)
				schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

				simpleSchema := getTestSchema()
				badSchemaRequest := router.CreateSchemaRequest{Schema: simpleSchema}
				schemaRequestValue := newRequestValue(tt, badSchemaRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				schemaService.CreateSchema(c)
				assert.Contains(tt, w.Body.String(), "invalid create schema request")

				// reset the http recorder
				w = httptest.NewRecorder()

				schemaRequest := router.CreateSchemaRequest{Name: "test schema", Schema: simpleSchema}
				schemaRequestValue = newRequestValue(tt, schemaRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)

				c = newRequestContext(w, req)
				schemaService.CreateSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateSchemaResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, resp.ID)

				// since the id is generated, we need to manually override it
				schemaRequest.Schema[schema.JSONSchemaIDProperty] = resp.Schema.ID()
				assert.JSONEq(tt, schemaRequest.Schema.String(), resp.Schema.String())
				assert.Equal(tt, schema.JSONSchemaType, resp.Type)
				assert.Empty(tt, resp.CredentialSchema)
				assert.NotEmpty(tt, resp.Schema)
			})

			t.Run("Test Create JsonCredentialSchema Schema", func(tt *testing.T) {
				bolt := test.ServiceStorage(tt)
				require.NotEmpty(tt, bolt)

				keyStoreService, _ := testKeyStoreService(tt, bolt)
				didService, _ := testDIDService(tt, bolt, keyStoreService, nil)
				schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

				simpleSchema := getTestSchema()
				badSchemaRequest := router.CreateSchemaRequest{
					Name:   "test schema",
					Schema: simpleSchema,
					CredentialSchemaRequest: &router.CredentialSchemaRequest{
						Issuer: "issuer",
					},
				}
				schemaRequestValue := newRequestValue(tt, badSchemaRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				schemaService.CreateSchema(c)
				assert.Contains(tt, w.Body.String(), "verificationMethodId is a required field")

				// reset the http recorder
				w = httptest.NewRecorder()

				// create an issuer for the credential schema
				issuerResp, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  "key",
					KeyType: crypto.Ed25519,
				})
				require.NoError(t, err)
				issuerID := issuerResp.DID.ID
				verificationMethodID := issuerResp.DID.VerificationMethod[0].ID

				// create the credential schema
				schemaRequest := router.CreateSchemaRequest{
					Name:   "test schema",
					Schema: simpleSchema,
					CredentialSchemaRequest: &router.CredentialSchemaRequest{
						Issuer:               issuerID,
						VerificationMethodID: verificationMethodID,
					},
				}
				schemaRequestValue = newRequestValue(tt, schemaRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)

				c = newRequestContext(w, req)
				schemaService.CreateSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateSchemaResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, resp.ID)

				assert.Empty(tt, resp.Schema)
				assert.NotEmpty(tt, resp.CredentialSchema)
				assert.Equal(tt, schema.JSONSchemaCredentialType, resp.Type)

				// decode the schema from the response and verify it
				_, _, cred, err := parsing.ToCredential(resp.CredentialSchema.String())
				assert.NoError(tt, err)
				credSubjectBytes, err := json.Marshal(cred.CredentialSubject[credential.VerifiableCredentialJSONSchemaProperty])
				assert.NoError(tt, err)
				var s schema.JSONSchema
				err = json.Unmarshal(credSubjectBytes, &s)
				assert.NoError(tt, err)
				assert.Equal(tt, schemaRequest.Issuer, cred.Issuer)

				// since the id is generated, we need to manually override it
				schemaRequest.Schema[schema.JSONSchemaIDProperty] = s.ID()
				delete(s, schema.JSONSchemaAdditionalIDProperty)
				assert.JSONEq(tt, schemaRequest.Schema.String(), s.String())
			})

			t.Run("Test Get Schema and Get Schemas", func(tt *testing.T) {
				bolt := test.ServiceStorage(tt)
				require.NotEmpty(tt, bolt)

				keyStoreService, _ := testKeyStoreService(tt, bolt)
				didService, _ := testDIDService(tt, bolt, keyStoreService, nil)
				schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

				// get schema that doesn't exist
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas/bad", nil)
				c := newRequestContext(w, req)
				schemaService.GetSchema(c)
				assert.Contains(tt, w.Body.String(), "cannot get schema without ID parameter")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get schema with invalid id
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas/bad", nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
				schemaService.GetSchema(c)
				assert.Contains(tt, w.Body.String(), "could not get schema with id: bad")

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get all schemas - get none
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas", nil)
				c = newRequestContext(w, req)
				schemaService.ListSchemas(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var getSchemasResp router.ListSchemasResponse
				err := json.NewDecoder(w.Body).Decode(&getSchemasResp)
				assert.NoError(tt, err)
				assert.Len(tt, getSchemasResp.Schemas, 0)

				// reset recorder between calls
				w = httptest.NewRecorder()

				// create a schema
				simpleSchema := getTestSchema()

				schemaRequest := router.CreateSchemaRequest{Name: "test schema", Schema: simpleSchema}
				schemaRequestValue := newRequestValue(tt, schemaRequest)
				createReq := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)

				c = newRequestContext(w, createReq)
				schemaService.CreateSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var createResp router.CreateSchemaResponse
				err = json.NewDecoder(w.Body).Decode(&createResp)
				assert.NoError(tt, err)

				assert.NotEmpty(tt, createResp.ID)

				// since the id is generated, we need to manually override it
				schemaRequest.Schema[schema.JSONSchemaIDProperty] = createResp.Schema.ID()
				assert.JSONEq(tt, schemaRequest.Schema.String(), createResp.Schema.String())

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get it back
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", createResp.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": createResp.ID})
				schemaService.GetSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var gotSchemaResp router.GetSchemaResponse
				err = json.NewDecoder(w.Body).Decode(&gotSchemaResp)
				assert.NoError(tt, err)

				assert.Contains(tt, gotSchemaResp.Schema.ID(), createResp.ID)
				assert.Equal(tt, createResp.Schema.Schema(), gotSchemaResp.Schema.Schema())

				// reset recorder between calls
				w = httptest.NewRecorder()

				// get all schemas - get none
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/schemas", nil)
				c = newRequestContext(w, req)
				schemaService.ListSchemas(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				err = json.NewDecoder(w.Body).Decode(&getSchemasResp)
				assert.NoError(tt, err)
				assert.Len(tt, getSchemasResp.Schemas, 1)
			})

			t.Run("Test Delete Schema", func(tt *testing.T) {
				bolt := test.ServiceStorage(tt)
				require.NotEmpty(tt, bolt)

				keyStoreService, _ := testKeyStoreService(tt, bolt)
				didService, _ := testDIDService(tt, bolt, keyStoreService, nil)
				schemaService := testSchemaRouter(tt, bolt, keyStoreService, didService)

				w := httptest.NewRecorder()

				// delete a schema that doesn't exist
				req := httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/schemas/bad", nil)
				c := newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
				schemaService.DeleteSchema(c)
				assert.Contains(tt, w.Body.String(), "deleting schema with id: bad")

				// create a schema
				simpleSchema := getTestSchema()

				schemaRequest := router.CreateSchemaRequest{Name: "test schema", Schema: simpleSchema}
				schemaRequestValue := newRequestValue(tt, schemaRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/schemas", schemaRequestValue)
				w = httptest.NewRecorder()
				c = newRequestContext(w, req)
				schemaService.CreateSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.CreateSchemaResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, resp.ID)

				// since the id is generated, we need to manually override it
				schemaRequest.Schema[schema.JSONSchemaIDProperty] = resp.Schema.ID()
				assert.JSONEq(tt, schemaRequest.Schema.String(), resp.Schema.String())

				// get schema by id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", resp.ID), nil)
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.ID})
				schemaService.GetSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				// delete it
				req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", resp.ID), nil)
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.ID})
				schemaService.DeleteSchema(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				// get it back
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/schemas/%s", resp.ID), nil)
				w = httptest.NewRecorder()
				c = newRequestContextWithParams(w, req, map[string]string{"id": resp.ID})
				schemaService.GetSchema(c)
				assert.Contains(tt, w.Body.String(), "schema not found")
			})
		})
	}
}

func getTestSchema() schema.JSONSchema {
	return map[string]any{
		"$id":         "https://example.com/foo.schema.json",
		"$schema":     "https://json-schema.org/draft-07/schema#",
		"name":        "test schema",
		"description": "test schema",
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
