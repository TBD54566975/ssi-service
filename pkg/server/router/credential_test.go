package router

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/status"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goccy/go-json"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
)

func TestCredentialRouter(t *testing.T) {

	t.Run("Nil Service", func(tt *testing.T) {
		credRouter, err := NewCredentialRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, credRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		credRouter, err := NewCredentialRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, credRouter)
		assert.Contains(tt, err.Error(), "could not create credential router with service type: test")
	})

	t.Run("Credential Service Test", func(tt *testing.T) {

		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credService, err := credential.NewCredentialService(serviceConfig, bolt, keyStoreService, didService.GetResolver(), schemaService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credService)

		// check type and status
		assert.Equal(tt, framework.Credential, credService.Type())
		assert.Equal(tt, framework.StatusReady, credService.Status().Status)

		// create a credential

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		issuer := issuerDID.DID.ID
		subject := "did:test:345"
		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:  issuer,
			Subject: subject,
			Data: map[string]any{
				"firstName": "Satoshi",
				"lastName":  "Nakamoto",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)
		assert.NotEmpty(tt, createdCred.CredentialJWT)

		cred := createdCred.Credential

		// make sure it has the right data
		assert.Equal(tt, issuer, cred.Issuer)
		assert.Equal(tt, subject, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
		assert.Equal(tt, "Satoshi", cred.CredentialSubject["firstName"])
		assert.Equal(tt, "Nakamoto", cred.CredentialSubject["lastName"])

		// get it back
		gotCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: cred.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotCred)

		// compare for object equality
		assert.Equal(tt, createdCred.CredentialJWT, gotCred.CredentialJWT)

		// get a cred that doesn't exist
		_, err = credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential not found with id: bad")

		// get by schema - no schema
		bySchema, err := credService.GetCredentialsBySchema(context.Background(), credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.Credentials, 1)
		assert.EqualValues(tt, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

		// get by subject
		bySubject, err := credService.GetCredentialsBySubject(context.Background(), credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.Credentials, 1)

		assert.Equal(tt, cred.ID, bySubject.Credentials[0].ID)
		assert.Equal(tt, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// get by issuer
		byIssuer, err := credService.GetCredentialsByIssuer(context.Background(), credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.Credentials, 1)

		assert.Equal(tt, cred.ID, byIssuer.Credentials[0].Credential.ID)
		assert.Equal(tt, cred.Issuer, byIssuer.Credentials[0].Credential.Issuer)

		// create another cred with the same issuer, different subject, different schema that doesn't exist
		_, err = credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    "did:abcd:efghi",
			JSONSchema: "https://test-schema.com",
			Data: map[string]any{
				"email": "satoshi@nakamoto.com",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "schema not found with id: https://test-schema.com")

		// create schema
		emailSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"email": map[string]any{
					"type": "string",
				},
			},
			"required":             []any{"email"},
			"additionalProperties": false,
		}
		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// create another cred with the same issuer, different subject, different schema that does exist
		createdCredWithSchema, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    "did:abcd:efghi",
			JSONSchema: createdSchema.ID,
			Data: map[string]any{
				"email": "satoshi@nakamoto.com",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCredWithSchema)

		// get by issuer
		byIssuer, err = credService.GetCredentialsByIssuer(context.Background(), credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.Credentials, 2)

		// make sure the schema and subject queries are consistent
		bySchema, err = credService.GetCredentialsBySchema(context.Background(), credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.Credentials, 1)

		assert.Equal(tt, cred.ID, bySchema.Credentials[0].ID)
		assert.EqualValues(tt, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

		bySubject, err = credService.GetCredentialsBySubject(context.Background(), credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.Credentials, 1)

		assert.Equal(tt, cred.ID, bySubject.Credentials[0].ID)
		assert.Equal(tt, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// delete a cred that doesn't exist (no error since idempotent)
		err = credService.DeleteCredential(context.Background(), credential.DeleteCredentialRequest{ID: "bad"})
		assert.NoError(tt, err)

		// delete a credential that does exist
		err = credService.DeleteCredential(context.Background(), credential.DeleteCredentialRequest{ID: cred.ID})
		assert.NoError(tt, err)

		// get it back
		_, err = credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: cred.ID})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("credential not found with id: %s", cred.ID))
	})

	t.Run("Credential Status List Test", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credService, err := credential.NewCredentialService(serviceConfig, bolt, keyStoreService, didService.GetResolver(), schemaService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credService)

		// check type and status
		assert.Equal(tt, framework.Credential, credService.Type())
		assert.Equal(tt, framework.StatusReady, credService.Status().Status)

		// create a did
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema
		emailSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"email": map[string]any{
					"type": "string",
				},
			},
			"required":             []any{"email"},
			"additionalProperties": false,
		}

		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		issuer := issuerDID.DID.ID
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: createdSchema.ID,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)
		assert.NotEmpty(tt, createdCred.CredentialJWT)

		credStatusMap, ok := createdCred.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.Contains(tt, credStatusMap["id"], fmt.Sprintf("v1/credentials/%s/status", createdCred.ID))
		assert.Contains(tt, credStatusMap["statusListCredential"], "v1/credentials/status")
		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		createdCredTwo, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: createdSchema.ID,
			Data: map[string]any{
				"email": "Satoshi2@Nakamoto2.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCredTwo)
		assert.NotEmpty(tt, createdCredTwo.CredentialJWT)

		credStatusMapTwo, ok := createdCredTwo.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.Contains(tt, credStatusMapTwo["id"], fmt.Sprintf("v1/credentials/%s/status", createdCredTwo.ID))
		assert.Contains(tt, credStatusMapTwo["statusListCredential"], "v1/credentials/status")
		assert.NotEmpty(tt, credStatusMapTwo["statusListIndex"])

		// Cred with same <issuer, schema> pair share the same statusListCredential
		assert.Equal(tt, credStatusMapTwo["statusListCredential"], credStatusMap["statusListCredential"])

		createdSchemaTwo, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchemaTwo)

		createdCredThree, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: createdSchemaTwo.ID,
			Data: map[string]any{
				"email": "Satoshi2@Nakamoto2.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCredThree)
		assert.NotEmpty(tt, createdCredThree.CredentialJWT)

		credStatusMapThree, ok := createdCredThree.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.Contains(tt, credStatusMapThree["id"], fmt.Sprintf("v1/credentials/%s/status", createdCredThree.ID))
		assert.Contains(tt, credStatusMapThree["statusListCredential"], "v1/credentials/status")
		assert.NotEmpty(tt, credStatusMapThree["statusListIndex"])

		// Cred with different <issuer, schema> pair have different statusListCredential
		assert.NotEqual(tt, credStatusMapThree["statusListCredential"], credStatusMap["statusListCredential"])
	})

	t.Run("Credential Status List Test No Schemas", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credService, err := credential.NewCredentialService(serviceConfig, bolt, keyStoreService, didService.GetResolver(), schemaService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credService)

		// check type and status
		assert.Equal(tt, framework.Credential, credService.Type())
		assert.Equal(tt, framework.StatusReady, credService.Status().Status)

		// create a did
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		issuer := issuerDID.DID.ID
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:  issuer,
			Subject: subject,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)
		assert.NotEmpty(tt, createdCred.CredentialJWT)

		credStatusMap, ok := createdCred.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.Contains(tt, credStatusMap["id"], fmt.Sprintf("v1/credentials/%s/status", createdCred.ID))
		assert.Contains(tt, credStatusMap["statusListCredential"], "v1/credentials/status")
		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		createdCredTwo, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:  issuer,
			Subject: subject,
			Data: map[string]any{
				"email": "Satoshi2@Nakamoto2.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCredTwo)
		assert.NotEmpty(tt, createdCredTwo.CredentialJWT)

		credStatusMapTwo, ok := createdCredTwo.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.Contains(tt, credStatusMapTwo["id"], fmt.Sprintf("v1/credentials/%s/status", createdCredTwo.ID))
		assert.Contains(tt, credStatusMapTwo["statusListCredential"], "v1/credentials/status")
		assert.NotEmpty(tt, credStatusMapTwo["statusListIndex"])

		// Cred with same <issuer, schema> pair share the same statusListCredential
		assert.Equal(tt, credStatusMapTwo["statusListCredential"], credStatusMap["statusListCredential"])

		emailSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"email": map[string]any{
					"type": "string",
				},
			},
			"required":             []any{"email"},
			"additionalProperties": false,
		}

		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		createdCredThree, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: createdSchema.ID,
			Data: map[string]any{
				"email": "Satoshi2@Nakamoto2.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCredThree)
		assert.NotEmpty(tt, createdCredThree.CredentialJWT)

		credStatusMapThree, ok := createdCredThree.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.Contains(tt, credStatusMapThree["id"], fmt.Sprintf("v1/credentials/%s/status", createdCredThree.ID))
		assert.Contains(tt, credStatusMapThree["statusListCredential"], "v1/credentials/status")
		assert.NotEmpty(tt, credStatusMapThree["statusListIndex"])

		// Cred with different <issuer, schema> pair have different statusListCredential
		assert.NotEqual(tt, credStatusMapThree["statusListCredential"], credStatusMap["statusListCredential"])
	})

	t.Run("Credential Status List Test Update Revoked Status", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "http://localhost:1234"}}
		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credService, err := credential.NewCredentialService(serviceConfig, bolt, keyStoreService, didService.GetResolver(), schemaService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credService)

		// check type and status
		assert.Equal(tt, framework.Credential, credService.Type())
		assert.Equal(tt, framework.StatusReady, credService.Status().Status)

		// create a did
		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema
		emailSchema := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"email": map[string]any{
					"type": "string",
				},
			},
			"required":             []any{"email"},
			"additionalProperties": false,
		}

		createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		issuer := issuerDID.DID.ID
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: createdSchema.ID,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)
		assert.NotEmpty(tt, createdCred.CredentialJWT)

		statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
		assert.NoError(tt, err)

		var statusEntry status.StatusList2021Entry
		err = json.Unmarshal(statusBytes, &statusEntry)
		assert.NoError(tt, err)

		assert.Contains(tt, statusEntry.ID, fmt.Sprintf("http://localhost:1234/v1/credentials/%s/status", createdCred.ID))
		assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
		assert.NotEmpty(tt, statusEntry.StatusListIndex)

		credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatus.Revoked, false)

		credStatusListStr := statusEntry.StatusListCredential

		_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
		assert.True(tt, ok)
		credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: credStatusListID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatusList.Credential.ID, statusEntry.StatusListCredential)

		credentialSubject := credStatusList.Container.Credential.CredentialSubject
		assert.NotEmpty(tt, credentialSubject)

		encodedList := credentialSubject["encodedList"]
		assert.NotEmpty(tt, encodedList)

		// Validate the StatusListIndex is not flipped in the credStatusList
		valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
		assert.NoError(tt, err)
		assert.False(tt, valid)

		updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Revoked: true})
		assert.NoError(tt, err)
		assert.Equal(tt, updatedStatus.Revoked, true)

		credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: credStatusListID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatusListAfterRevoke.Credential.ID, statusEntry.StatusListCredential)

		// Validate the StatusListIndex in flipped in the credStatusList
		valid, err = status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusListAfterRevoke.Credential)
		assert.NoError(tt, err)
		assert.True(tt, valid)

		credentialSubjectAfterRevoke := credStatusListAfterRevoke.Container.Credential.CredentialSubject
		assert.NotEmpty(tt, credentialSubjectAfterRevoke)

		encodedListAfterRevoke := credentialSubjectAfterRevoke["encodedList"]
		assert.NotEmpty(tt, encodedListAfterRevoke)

		assert.NotEqualValues(tt, encodedListAfterRevoke, encodedList)
	})

	t.Run("Existing Status List Indexes Used After Restart", func(tt *testing.T) {
		statusListIndexNamespace := "status-list-index"

		statusListIndexesKey := "status-list-indexes"
		currentListIndexKey := "current-list-index"

		bolt := setupTestDB(tt)
		assert.NotNil(tt, bolt)

		// Make sure there is nothing in DB before we create storage
		value, err := bolt.Read(context.Background(), statusListIndexNamespace, currentListIndexKey)
		assert.NoError(tt, err)
		assert.Empty(tt, value)

		value, err = bolt.Read(context.Background(), statusListIndexNamespace, statusListIndexesKey)
		assert.NoError(tt, err)
		assert.Empty(tt, value)

		exists, err := bolt.Exists(context.Background(), statusListIndexNamespace, currentListIndexKey)
		assert.NoError(tt, err)
		assert.False(tt, exists)

		exists, err = bolt.Exists(context.Background(), statusListIndexNamespace, statusListIndexesKey)
		assert.NoError(tt, err)
		assert.False(tt, exists)

		// Create the storage
		credStorage, err := credential.NewCredentialStorage(bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credStorage)

		// Make sure that values are there after we create a new credential storage
		exists, err = bolt.Exists(context.Background(), statusListIndexNamespace, currentListIndexKey)
		assert.NoError(tt, err)
		assert.True(tt, exists)

		exists, err = bolt.Exists(context.Background(), statusListIndexNamespace, statusListIndexesKey)
		assert.NoError(tt, err)
		assert.True(tt, exists)

		value, err = bolt.Read(context.Background(), statusListIndexNamespace, currentListIndexKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, value)

		statusListIndexes, err := bolt.Read(context.Background(), statusListIndexNamespace, statusListIndexesKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, value)

		// "Restart" the service
		credStorage, err = credential.NewCredentialStorage(bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credStorage)

		exists, err = bolt.Exists(context.Background(), statusListIndexNamespace, currentListIndexKey)
		assert.NoError(tt, err)
		assert.True(tt, exists)

		exists, err = bolt.Exists(context.Background(), statusListIndexNamespace, statusListIndexesKey)
		assert.NoError(tt, err)
		assert.True(tt, exists)

		value, err = bolt.Read(context.Background(), statusListIndexNamespace, currentListIndexKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, value)

		statusListIndexesAfterRestart, err := bolt.Read(context.Background(), statusListIndexNamespace, statusListIndexesKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, statusListIndexesAfterRestart)

		assert.Equal(tt, statusListIndexes, statusListIndexesAfterRestart)
	})

	t.Run("Create Suspendable Credential", func(tt *testing.T) {
		issuer, schema, credService := createCredServicePrereqs(tt)
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: schema,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Suspendable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)
		assert.NotEmpty(tt, createdCred.CredentialJWT)

		statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
		assert.NoError(tt, err)

		var statusEntry status.StatusList2021Entry
		err = json.Unmarshal(statusBytes, &statusEntry)
		assert.NoError(tt, err)

		assert.Contains(tt, statusEntry.ID, fmt.Sprintf("http://localhost:1234/v1/credentials/%s/status", createdCred.ID))
		assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
		assert.NotEmpty(tt, statusEntry.StatusListIndex)

		credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatus.Revoked, false)
		assert.Equal(tt, credStatus.Suspended, false)

		credStatusListStr := statusEntry.StatusListCredential

		_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
		assert.True(tt, ok)
		credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: credStatusListID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatusList.Credential.ID, statusEntry.StatusListCredential)

		credentialSubject := credStatusList.Container.Credential.CredentialSubject
		assert.NotEmpty(tt, credentialSubject)

		encodedList := credentialSubject["encodedList"]
		assert.NotEmpty(tt, encodedList)

		// Validate the StatusListIndex is not flipped in the credStatusList
		valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
		assert.NoError(tt, err)
		assert.False(tt, valid)
	})

	t.Run("Update Suspendable Credential To Suspended", func(tt *testing.T) {
		issuer, schema, credService := createCredServicePrereqs(tt)
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: schema,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Suspendable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)
		assert.NotEmpty(tt, createdCred.CredentialJWT)

		statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
		assert.NoError(tt, err)

		var statusEntry status.StatusList2021Entry
		err = json.Unmarshal(statusBytes, &statusEntry)
		assert.NoError(tt, err)

		assert.Contains(tt, statusEntry.ID, fmt.Sprintf("http://localhost:1234/v1/credentials/%s/status", createdCred.ID))
		assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
		assert.NotEmpty(tt, statusEntry.StatusListIndex)

		credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatus.Revoked, false)
		assert.Equal(tt, credStatus.Suspended, false)

		credStatusListStr := statusEntry.StatusListCredential

		_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
		assert.True(tt, ok)
		credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: credStatusListID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatusList.Credential.ID, statusEntry.StatusListCredential)

		credentialSubject := credStatusList.Container.Credential.CredentialSubject
		assert.NotEmpty(tt, credentialSubject)

		encodedList := credentialSubject["encodedList"]
		assert.NotEmpty(tt, encodedList)

		// Validate the StatusListIndex is not flipped in the credStatusList
		valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
		assert.NoError(tt, err)
		assert.False(tt, valid)

		updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: true})
		assert.NoError(tt, err)
		assert.Equal(tt, updatedStatus.Suspended, true)
		assert.Equal(tt, updatedStatus.Revoked, false)

		credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: credStatusListID})
		assert.NoError(tt, err)
		assert.Equal(tt, credStatusListAfterRevoke.Credential.ID, statusEntry.StatusListCredential)

		// Validate the StatusListIndex in flipped in the credStatusList
		valid, err = status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusListAfterRevoke.Credential)
		assert.NoError(tt, err)
		assert.True(tt, valid)

		credentialSubjectAfterRevoke := credStatusListAfterRevoke.Container.Credential.CredentialSubject
		assert.NotEmpty(tt, credentialSubjectAfterRevoke)

		encodedListAfterSuspended := credentialSubjectAfterRevoke["encodedList"]
		assert.NotEmpty(tt, encodedListAfterSuspended)

		assert.NotEqualValues(tt, encodedListAfterSuspended, encodedList)
	})

	t.Run("Create Suspendable and Revocable Credential Should Be Error", func(tt *testing.T) {
		issuer, schema, credService := createCredServicePrereqs(tt)
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: schema,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable:   true,
			Suspendable: true,
		})

		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "credential may have at most one status")
		assert.Empty(tt, createdCred)
	})

	t.Run("Update Suspendable and Revocable Credential Should Be Error", func(tt *testing.T) {
		issuer, schema, credService := createCredServicePrereqs(tt)
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: schema,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Suspendable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Revoked: true, Suspended: true})
		assert.Nil(tt, updatedStatus)
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "cannot update both suspended and revoked status")
	})

	t.Run("Update Suspended On Revoked Credential Should Be Error", func(tt *testing.T) {
		issuer, schema, credService := createCredServicePrereqs(tt)
		subject := "did:test:345"

		createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    subject,
			JSONSchema: schema,
			Data: map[string]any{
				"email": "Satoshi@Nakamoto.btc",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		})

		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCred)

		updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: true})
		assert.Nil(tt, updatedStatus)
		assert.Error(tt, err)
		assert.ErrorContains(tt, err, "has a different status purpose<revocation> value than the status credential<suspension>")
	})

}

func createCredServicePrereqs(tt *testing.T) (string, string, credential.Service) {
	bolt := setupTestDB(tt)
	require.NotNil(tt, bolt)

	serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "http://localhost:1234"}}
	keyStoreService := testKeyStoreService(tt, bolt)
	didService := testDIDService(tt, bolt, keyStoreService)
	schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
	credService, err := credential.NewCredentialService(serviceConfig, bolt, keyStoreService, didService.GetResolver(), schemaService)
	require.NoError(tt, err)
	require.NotEmpty(tt, credService)

	// check type and status
	require.Equal(tt, framework.Credential, credService.Type())
	require.Equal(tt, framework.StatusReady, credService.Status().Status)

	// create a did
	issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
	require.NoError(tt, err)
	require.NotEmpty(tt, issuerDID)

	// create a schema
	emailSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"email": map[string]any{
				"type": "string",
			},
		},
		"required":             []any{"email"},
		"additionalProperties": false,
	}

	createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
	require.NoError(tt, err)
	require.NotEmpty(tt, createdSchema)

	return issuerDID.DID.ID, createdSchema.ID, *credService
}
