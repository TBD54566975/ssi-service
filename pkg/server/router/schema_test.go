package router

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
)

func TestSchemaRouter(t *testing.T) {

	t.Run("Nil Service", func(tt *testing.T) {
		schemaRouter, err := NewSchemaRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, schemaRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		schemaRouter, err := NewSchemaRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, schemaRouter)
		assert.Contains(tt, err.Error(), "could not create schema router with service type: test")
	})

	t.Run("Schema Service Test", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		serviceConfig := config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "schema"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService, err := schema.NewSchemaService(serviceConfig, bolt, keyStoreService, didService.GetResolver())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, schemaService)

		// check type and status
		assert.Equal(tt, framework.Schema, schemaService.Type())
		assert.Equal(tt, framework.StatusReady, schemaService.Status().Status)

		// get all schemas (none)
		gotSchemas, err := schemaService.GetSchemas(context.Background())
		assert.NoError(tt, err)
		assert.Empty(tt, gotSchemas.Schemas)

		// get schema that doesn't exist
		_, err = schemaService.GetSchema(context.Background(), schema.GetSchemaRequest{ID: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting schema")

		// create a schema
		simpleSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"foo": map[string]any{
					"type": "string",
				},
			},
			"required":             []any{"foo"},
			"additionalProperties": false,
		}
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
		assert.NotEmpty(tt, createdSchema.ID)
		assert.Equal(tt, "me", createdSchema.Schema.Author)
		assert.Equal(tt, "simple schema", createdSchema.Schema.Name)

		// get schema by ID
		gotSchema, err := schemaService.GetSchema(context.Background(), schema.GetSchemaRequest{ID: createdSchema.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchema)
		assert.EqualValues(tt, createdSchema.Schema, gotSchema.Schema)

		// get all schemas, expect one
		gotSchemas, err = schemaService.GetSchemas(context.Background())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchemas.Schemas)
		assert.Len(tt, gotSchemas.Schemas, 1)

		// store another
		createdSchema, err = schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema 2", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
		assert.NotEmpty(tt, createdSchema.ID)
		assert.Equal(tt, "me", createdSchema.Schema.Author)
		assert.Equal(tt, "simple schema 2", createdSchema.Schema.Name)

		// get all schemas, expect two
		gotSchemas, err = schemaService.GetSchemas(context.Background())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchemas.Schemas)
		assert.Len(tt, gotSchemas.Schemas, 2)

		// make sure their IDs are different
		assert.True(tt, gotSchemas.Schemas[0].ID != gotSchemas.Schemas[1].ID)

		// delete the first schema
		err = schemaService.DeleteSchema(context.Background(), schema.DeleteSchemaRequest{ID: gotSchemas.Schemas[0].ID})
		assert.NoError(tt, err)

		// get all schemas, expect one
		gotSchemas, err = schemaService.GetSchemas(context.Background())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchemas.Schemas)
		assert.Len(tt, gotSchemas.Schemas, 1)
	})
}

func TestSchemaSigning(t *testing.T) {

	t.Run("Unsigned Schema Test", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		serviceConfig := config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "schema"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService, err := schema.NewSchemaService(serviceConfig, bolt, keyStoreService, didService.GetResolver())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, schemaService)

		// check type and status
		assert.Equal(tt, framework.Schema, schemaService.Type())
		assert.Equal(tt, framework.StatusReady, schemaService.Status().Status)

		// create a schema and don't sign it
		simpleSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"foo": map[string]any{
					"type": "string",
				},
			},
			"required":             []any{"foo"},
			"additionalProperties": false,
		}
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
		assert.NotEmpty(tt, createdSchema.ID)
		assert.Empty(tt, createdSchema.SchemaJWT)
		assert.Equal(tt, "me", createdSchema.Schema.Author)
		assert.Equal(tt, "simple schema", createdSchema.Schema.Name)

		// missing DID
		createdSchema, err = schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: simpleSchema, Sign: true})
		assert.Error(tt, err)
		assert.Empty(tt, createdSchema)
		assert.Contains(tt, err.Error(), "could not get key for signing schema for author<me>")

		// create an author DID
		authorDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, authorDID)

		createdSchema, err = schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: authorDID.DID.ID, Name: "simple schema", Schema: simpleSchema, Sign: true})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
		assert.NotEmpty(tt, createdSchema.SchemaJWT)

		// verify the schema
		verifiedSchema, err := schemaService.VerifySchema(schema.VerifySchemaRequest{SchemaJWT: *createdSchema.SchemaJWT})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedSchema)
		assert.True(tt, verifiedSchema.Verified)

		// verify a bad schema
		verifiedSchema, err = schemaService.VerifySchema(schema.VerifySchemaRequest{SchemaJWT: "bad"})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedSchema)
		assert.False(tt, verifiedSchema.Verified)
		assert.Contains(tt, verifiedSchema.Reason, "could not verify schema")
	})
}
