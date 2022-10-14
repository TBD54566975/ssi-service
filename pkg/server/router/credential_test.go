package router

import (
	"fmt"
	"os"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestCredentialRouter(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

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
		bolt, err := storage.NewBoltDB()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, bolt)

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

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		issuer := issuerDID.DID.ID
		subject := "did:test:345"
		createdCred, err := credService.CreateCredential(credential.CreateCredentialRequest{
			Issuer:  issuer,
			Subject: subject,
			Data: map[string]interface{}{
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
		gotCred, err := credService.GetCredential(credential.GetCredentialRequest{ID: cred.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotCred)

		// compare for object equality
		assert.Equal(tt, createdCred.CredentialJWT, gotCred.CredentialJWT)

		// get a cred that doesn't exist
		_, err = credService.GetCredential(credential.GetCredentialRequest{ID: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential not found with id: bad")

		// get by schema - no schema
		bySchema, err := credService.GetCredentialsBySchema(credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.Credentials, 1)
		assert.EqualValues(tt, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

		// get by subject
		bySubject, err := credService.GetCredentialsBySubject(credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.Credentials, 1)

		assert.Equal(tt, cred.ID, bySubject.Credentials[0].ID)
		assert.Equal(tt, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// get by issuer
		byIssuer, err := credService.GetCredentialsByIssuer(credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.Credentials, 1)

		assert.Equal(tt, cred.ID, byIssuer.Credentials[0].Credential.ID)
		assert.Equal(tt, cred.Issuer, byIssuer.Credentials[0].Credential.Issuer)

		// create another cred with the same issuer, different subject, different schema that doesn't exist
		_, err = credService.CreateCredential(credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    "did:abcd:efghi",
			JSONSchema: "https://test-schema.com",
			Data: map[string]interface{}{
				"email": "satoshi@nakamoto.com",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "schema not found with id: https://test-schema.com")

		// create schema
		emailSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"email": map[string]interface{}{
					"type": "string",
				},
			},
			"required":             []interface{}{"email"},
			"additionalProperties": false,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: emailSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		// create another cred with the same issuer, different subject, different schema that does exist
		createdCredWithSchema, err := credService.CreateCredential(credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    "did:abcd:efghi",
			JSONSchema: createdSchema.ID,
			Data: map[string]interface{}{
				"email": "satoshi@nakamoto.com",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdCredWithSchema)

		// get by issuer
		byIssuer, err = credService.GetCredentialsByIssuer(credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.Credentials, 2)

		// make sure the schema and subject queries are consistent
		bySchema, err = credService.GetCredentialsBySchema(credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.Credentials, 1)

		assert.Equal(tt, cred.ID, bySchema.Credentials[0].ID)
		assert.EqualValues(tt, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

		bySubject, err = credService.GetCredentialsBySubject(credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.Credentials, 1)

		assert.Equal(tt, cred.ID, bySubject.Credentials[0].ID)
		assert.Equal(tt, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// delete a cred that doesn't exist (no error since idempotent)
		err = credService.DeleteCredential(credential.DeleteCredentialRequest{ID: "bad"})
		assert.NoError(tt, err)

		// delete a credential that does exist
		err = credService.DeleteCredential(credential.DeleteCredentialRequest{ID: cred.ID})
		assert.NoError(tt, err)

		// get it back
		_, err = credService.GetCredential(credential.GetCredentialRequest{ID: cred.ID})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("credential not found with id: %s", cred.ID))
	})
}
