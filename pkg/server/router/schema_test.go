package router

import (
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"os"
	"testing"
)

func TestSchemaRouter(t *testing.T) {

	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

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

	t.Run("JSONSchema Service Test", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

		serviceConfig := config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "schema"}}
		schemaService, err := schema.NewSchemaService(serviceConfig, bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, schemaService)

		// check type and status
		assert.Equal(tt, framework.Schema, schemaService.Type())
		assert.Equal(tt, framework.StatusReady, schemaService.Status().Status)

		// get all schemas (none)
		gotSchemas, err := schemaService.GetSchemas()
		assert.NoError(tt, err)
		assert.Empty(tt, gotSchemas)
		assert.Equal(tt, 0, len(gotSchemas.Schemas))

		// get schema that doesn't exist
		_, err = schemaService.GetSchemaByID(schema.GetSchemaByIDRequest{ID: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "error getting schema")

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
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
		assert.NotEmpty(tt, createdSchema.ID)
		assert.Equal(tt, "me", createdSchema.Schema.Author)
		assert.Equal(tt, "simple schema", createdSchema.Schema.Name)

		// get schema by ID
		gotSchema, err := schemaService.GetSchemaByID(schema.GetSchemaByIDRequest{ID: createdSchema.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchema)
		assert.EqualValues(tt, createdSchema.Schema, gotSchema.Schema)

		// get all schemas, expect one
		gotSchemas, err = schemaService.GetSchemas()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchemas.Schemas)
		assert.Len(tt, gotSchemas.Schemas, 1)

		// store another
		createdSchema, err = schemaService.CreateSchema(schema.CreateSchemaRequest{Author: "me", Name: "simple schema 2", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
		assert.NotEmpty(tt, createdSchema.ID)
		assert.Equal(tt, "me", createdSchema.Schema.Author)
		assert.Equal(tt, "simple schema 2", createdSchema.Schema.Name)

		// get all schemas, expect two
		gotSchemas, err = schemaService.GetSchemas()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotSchemas.Schemas)
		assert.Len(tt, gotSchemas.Schemas, 2)

		// make sure their IDs are different
		assert.True(tt, gotSchemas.Schemas[0].ID != gotSchemas.Schemas[1].ID)
	})
}
