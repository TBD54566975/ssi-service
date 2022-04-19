package router

import (
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
	"os"
	"testing"
)

func TestSchemaRouter(t *testing.T) {

	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Nil Service", func(tt *testing.T) {
		schemaRouter, err := NewSchemaRouter(nil, nil)
		assert.Error(tt, err)
		assert.Empty(tt, schemaRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		schemaRouter, err := NewSchemaRouter(&testService{}, nil)
		assert.Error(tt, err)
		assert.Empty(tt, schemaRouter)
		assert.Contains(tt, err.Error(), "could not create schema router with service type: test")
	})

	t.Run("Schema Service Test", func(tt *testing.T) {
		logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)

		bolt, err := storage.NewBoltDB(logger)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

		schemaService, err := schema.NewSchemaService(logger, bolt)
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

		// create a bad schema
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Schema: map[string]interface{}{
			"bad": "bad",
		}})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)
	})
}
