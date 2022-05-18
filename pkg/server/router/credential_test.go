package router

import (
	"fmt"
	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"os"
	"testing"
	"time"
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
		credService, err := credential.NewCredentialService(serviceConfig, bolt)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credService)

		// check type and status
		assert.Equal(tt, framework.Credential, credService.Type())
		assert.Equal(tt, framework.StatusReady, credService.Status().Status)

		// create a credential
		issuer := "did:test:123"
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
		assert.NotEmpty(tt, createdCred.Credential)

		// make sure it has the right data
		assert.Equal(tt, issuer, createdCred.Credential.Issuer)
		assert.Equal(tt, subject, createdCred.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
		assert.Equal(tt, "Satoshi", createdCred.Credential.CredentialSubject["firstName"])
		assert.Equal(tt, "Nakamoto", createdCred.Credential.CredentialSubject["lastName"])

		// get it back
		gotCred, err := credService.GetCredential(credential.GetCredentialRequest{ID: createdCred.Credential.ID})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotCred)

		// marshal to JSON and compare for object equality
		createdBytes, err := json.Marshal(createdCred.Credential)
		assert.NoError(tt, err)
		gotBytes, err := json.Marshal(gotCred.Credential)
		assert.NoError(tt, err)
		assert.Equal(tt, createdBytes, gotBytes)

		// get a cred that doesn't exist
		_, err = credService.GetCredential(credential.GetCredentialRequest{ID: "bad"})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential not found with id: bad")

		// get by schema - no schema
		bySchema, err := credService.GetCredentialsBySchema(credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.Credentials, 1)
		assert.Equal(tt, bySchema.Credentials[0].ID, createdCred.Credential.ID)
		assert.EqualValues(tt, bySchema.Credentials[0].CredentialSchema, createdCred.Credential.CredentialSchema)

		// get by subject
		bySubject, err := credService.GetCredentialsBySubject(credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.Credentials, 1)
		assert.Equal(tt, bySubject.Credentials[0].ID, createdCred.Credential.ID)
		assert.Equal(tt, bySubject.Credentials[0].CredentialSubject[credsdk.VerifiableCredentialIDProperty], createdCred.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// get by issuer
		byIssuer, err := credService.GetCredentialsByIssuer(credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.Credentials, 1)
		assert.Equal(tt, byIssuer.Credentials[0].ID, createdCred.Credential.ID)
		assert.Equal(tt, byIssuer.Credentials[0].Issuer, createdCred.Credential.Issuer)

		// create another cred with the same issuer, different subject, different schema
		anotherCreatedCred, err := credService.CreateCredential(credential.CreateCredentialRequest{
			Issuer:     issuer,
			Subject:    "did:abcd:efghi",
			JSONSchema: "https://test-schema.com",
			Data: map[string]interface{}{
				"email": "satoshi@nakamoto.com",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, anotherCreatedCred)

		// get by issuer
		byIssuer, err = credService.GetCredentialsByIssuer(credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.Credentials, 2)

		// make sure the schema and subject queries are consistent
		bySchema, err = credService.GetCredentialsBySchema(credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.Credentials, 1)
		assert.Equal(tt, bySchema.Credentials[0].ID, createdCred.Credential.ID)
		assert.EqualValues(tt, bySchema.Credentials[0].CredentialSchema, createdCred.Credential.CredentialSchema)

		bySubject, err = credService.GetCredentialsBySubject(credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.Credentials, 1)
		assert.Equal(tt, bySubject.Credentials[0].ID, createdCred.Credential.ID)
		assert.Equal(tt, bySubject.Credentials[0].CredentialSubject[credsdk.VerifiableCredentialIDProperty], createdCred.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// delete a cred that doesn't exist (no error since idempotent)
		err = credService.DeleteCredential(credential.DeleteCredentialRequest{ID: "bad"})
		assert.NoError(tt, err)

		// delete a credential that does exist
		err = credService.DeleteCredential(credential.DeleteCredentialRequest{ID: createdCred.Credential.ID})
		assert.NoError(tt, err)

		// get it back
		_, err = credService.GetCredential(credential.GetCredentialRequest{ID: createdCred.Credential.ID})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("credential not found with id: %s", createdCred.Credential.ID))
	})
}
