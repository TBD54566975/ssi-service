package router

import (
	"context"
	"testing"

	credschema "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
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

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {

			t.Run("Schema Service Test", func(tt *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(tt, db)

				serviceConfig := config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "schema"}}
				keyStoreService := testKeyStoreService(tt, db)
				didService := testDIDService(tt, db, keyStoreService)
				schemaService, err := schema.NewSchemaService(serviceConfig, db, keyStoreService, didService.GetResolver())
				assert.NoError(tt, err)
				assert.NotEmpty(tt, schemaService)

				// check type and status
				assert.Equal(tt, framework.Schema, schemaService.Type())
				assert.Equal(tt, framework.StatusReady, schemaService.Status().Status)

				// get all schemas (none)
				gotSchemas, err := schemaService.ListSchemas(context.Background())
				assert.NoError(tt, err)
				assert.Empty(tt, gotSchemas.Schemas)

				// get schema that doesn't exist
				_, err = schemaService.GetSchema(context.Background(), schema.GetSchemaRequest{ID: "bad"})
				assert.Error(tt, err)
				assert.Contains(tt, err.Error(), "error getting schema")

				// create a schema
				simpleSchema := map[string]any{
					"$schema": "https://json-schema.org/draft-07/schema",
					"type":    "object",
					"properties": map[string]any{
						"credentialSubject": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"id": map[string]any{
									"type": "string",
								},
								"firstName": map[string]any{
									"type": "string",
								},
								"lastName": map[string]any{
									"type": "string",
								},
							},
							"required": []any{"firstName", "lastName"},
						},
					},
				}
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: "me", Name: "simple schema", Schema: simpleSchema})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)
				assert.NotEmpty(tt, createdSchema.ID)
				assert.Equal(tt, "simple schema", createdSchema.Schema.Name())

				// get schema by ID
				gotSchema, err := schemaService.GetSchema(context.Background(), schema.GetSchemaRequest{ID: createdSchema.ID})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotSchema)
				assert.EqualValues(tt, createdSchema.Schema, gotSchema.Schema)

				// get all schemas, expect one
				gotSchemas, err = schemaService.ListSchemas(context.Background())
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotSchemas.Schemas)
				assert.Len(tt, gotSchemas.Schemas, 1)

				// store another
				createdSchema, err = schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: "me", Name: "simple schema 2", Schema: simpleSchema})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)
				assert.NotEmpty(tt, createdSchema.ID)
				assert.Equal(tt, "simple schema 2", createdSchema.Schema.Name())
				assert.Equal(tt, credschema.JSONSchema2023Type, createdSchema.Type)

				// get all schemas, expect two
				gotSchemas, err = schemaService.ListSchemas(context.Background())
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotSchemas.Schemas)
				assert.Len(tt, gotSchemas.Schemas, 2)

				// make sure their IDs are different
				assert.True(tt, gotSchemas.Schemas[0].ID != gotSchemas.Schemas[1].ID)

				// delete the first schema
				err = schemaService.DeleteSchema(context.Background(), schema.DeleteSchemaRequest{ID: gotSchemas.Schemas[0].ID})
				assert.NoError(tt, err)

				// get all schemas, expect one
				gotSchemas, err = schemaService.ListSchemas(context.Background())
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotSchemas.Schemas)
				assert.Len(tt, gotSchemas.Schemas, 1)
			})
		})
	}
}

func TestSchemaSigning(t *testing.T) {

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Unsigned Schema Test", func(tt *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(tt, db)

				serviceConfig := config.SchemaServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "schema"}}
				keyStoreService := testKeyStoreService(tt, db)
				didService := testDIDService(tt, db, keyStoreService)
				schemaService, err := schema.NewSchemaService(serviceConfig, db, keyStoreService, didService.GetResolver())
				assert.NoError(tt, err)
				assert.NotEmpty(tt, schemaService)

				// check type and status
				assert.Equal(tt, framework.Schema, schemaService.Type())
				assert.Equal(tt, framework.StatusReady, schemaService.Status().Status)

				// create a schema and don't sign it
				simpleSchema := map[string]any{
					"$schema": "https://json-schema.org/draft-07/schema",
					"type":    "object",
					"properties": map[string]any{
						"credentialSubject": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"id": map[string]any{
									"type": "string",
								},
								"firstName": map[string]any{
									"type": "string",
								},
								"lastName": map[string]any{
									"type": "string",
								},
							},
							"required": []any{"firstName", "lastName"},
						},
					},
				}
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: "me", Name: "simple schema", Schema: simpleSchema})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)
				assert.NotEmpty(tt, createdSchema.ID)
				assert.Equal(tt, "simple schema", createdSchema.Schema.Name())
			})
		})
	}
}
