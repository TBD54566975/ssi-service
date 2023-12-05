package router

import (
	"context"
	"testing"

	credschema "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestSchemaRouter(t *testing.T) {

	t.Run("Nil Service", func(t *testing.T) {
		schemaRouter, err := NewSchemaRouter(nil)
		assert.Error(t, err)
		assert.Empty(t, schemaRouter)
		assert.Contains(t, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(t *testing.T) {
		schemaRouter, err := NewSchemaRouter(&testService{})
		assert.Error(t, err)
		assert.Empty(t, schemaRouter)
		assert.Contains(t, err.Error(), "could not create schema router with service type: test")
	})

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {

			t.Run("Schema Service Test", func(t *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(t, db)

				keyStoreService := testKeyStoreService(t, db)
				didService := testDIDService(t, db, keyStoreService)
				schemaService, err := schema.NewSchemaService(db, keyStoreService, didService.GetResolver())
				assert.NoError(t, err)
				assert.NotEmpty(t, schemaService)

				// check type and status
				assert.Equal(t, framework.Schema, schemaService.Type())
				assert.Equal(t, framework.StatusReady, schemaService.Status().Status)

				// get all schemas (none)
				gotSchemas, err := schemaService.ListSchemas(context.Background(), schema.ListSchemasRequest{})
				assert.NoError(t, err)
				assert.Empty(t, gotSchemas.Schemas)

				// get schema that doesn't exist
				_, err = schemaService.GetSchema(context.Background(), schema.GetSchemaRequest{ID: "bad"})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "error getting schema")

				// create a schema
				simpleSchema := getSimpleSchema()
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: "me", Name: "simple schema", Schema: simpleSchema})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)
				assert.NotEmpty(t, createdSchema.ID)
				assert.Equal(t, "simple schema", createdSchema.Schema.Name())

				// get schema by ID
				gotSchema, err := schemaService.GetSchema(context.Background(), schema.GetSchemaRequest{ID: createdSchema.ID})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotSchema)
				assert.EqualValues(t, createdSchema.Schema, gotSchema.Schema)

				// get all schemas, expect one
				gotSchemas, err = schemaService.ListSchemas(context.Background(), schema.ListSchemasRequest{})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotSchemas.Schemas)
				assert.Len(t, gotSchemas.Schemas, 1)

				// store another
				createdSchema, err = schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: "me", Name: "simple schema 2", Schema: simpleSchema})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)
				assert.NotEmpty(t, createdSchema.ID)
				assert.Equal(t, "simple schema 2", createdSchema.Schema.Name())
				assert.Equal(t, credschema.JSONSchemaType, createdSchema.Type)

				// get all schemas, expect two
				gotSchemas, err = schemaService.ListSchemas(context.Background(), schema.ListSchemasRequest{})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotSchemas.Schemas)
				assert.Len(t, gotSchemas.Schemas, 2)

				// make sure their IDs are different
				assert.True(t, gotSchemas.Schemas[0].ID != gotSchemas.Schemas[1].ID)

				// delete the first schema
				err = schemaService.DeleteSchema(context.Background(), schema.DeleteSchemaRequest{ID: gotSchemas.Schemas[0].ID})
				assert.NoError(t, err)

				// get all schemas, expect one
				gotSchemas, err = schemaService.ListSchemas(context.Background(), schema.ListSchemasRequest{})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotSchemas.Schemas)
				assert.Len(t, gotSchemas.Schemas, 1)
			})
		})
	}
}

func TestSchemaSigning(t *testing.T) {

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Unsigned Schema Test", func(t *testing.T) {
				db := test.ServiceStorage(t)
				assert.NotEmpty(t, db)

				keyStoreService := testKeyStoreService(t, db)
				didService := testDIDService(t, db, keyStoreService)
				schemaService, err := schema.NewSchemaService(db, keyStoreService, didService.GetResolver())
				assert.NoError(t, err)
				assert.NotEmpty(t, schemaService)

				// check type and status
				assert.Equal(t, framework.Schema, schemaService.Type())
				assert.Equal(t, framework.StatusReady, schemaService.Status().Status)

				// create a schema and don't sign it
				simpleSchema := getSimpleSchema()
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: "me", Name: "simple schema", Schema: simpleSchema})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)
				assert.NotEmpty(t, createdSchema.ID)
				assert.Equal(t, "simple schema", createdSchema.Schema.Name())
			})
		})

		t.Run("Signing schema with revoked key test", func(t *testing.T) {
			db := test.ServiceStorage(t)
			assert.NotEmpty(t, db)

			keyStoreService := testKeyStoreService(t, db)
			didService := testDIDService(t, db, keyStoreService)
			schemaService, err := schema.NewSchemaService(db, keyStoreService, didService.GetResolver())
			assert.NoError(t, err)
			assert.NotEmpty(t, schemaService)

			// Create a DID
			controllerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
			assert.NoError(t, err)
			assert.NotEmpty(t, controllerDID)
			didID := controllerDID.DID.ID

			// Create a key controlled by the DID
			keyID := controllerDID.DID.VerificationMethod[0].ID
			privateKey := "2dEPd7mA3aiuh2gky8tTPiCkyMwf8tBNUMZwRzeVxVJnJFGTbdLGUBcx51DCNyFWRjTG9bduvyLRStXSCDMFXULY"

			err = keyStoreService.StoreKey(context.Background(), keystore.StoreKeyRequest{ID: keyID, Type: crypto.Ed25519, Controller: didID, PrivateKeyBase58: privateKey})
			assert.NoError(t, err)

			// Revoke the key
			err = keyStoreService.RevokeKey(context.Background(), keystore.RevokeKeyRequest{ID: keyID})
			assert.NoError(t, err)

			// create a schema with the revoked key, it fails
			_, err = schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: controllerDID.DID.ID, Name: "schema (revoked key)", Schema: getEmailSchema(), FullyQualifiedVerificationMethodID: keyID})
			assert.Error(t, err)
			assert.ErrorContains(t, err, "cannot use revoked key")
		})
	}
}

func getSimpleSchema() map[string]any {
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
	return simpleSchema
}
