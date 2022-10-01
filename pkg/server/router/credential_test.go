package router

import (
	"fmt"
	"os"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
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
		credService, err := credential.NewCredentialService(serviceConfig, bolt, keyStoreService)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, credService)

		// check type and status
		assert.Equal(tt, framework.Credential, credService.Type())
		assert.Equal(tt, framework.StatusReady, credService.Status().Status)

		// create a credential

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{Method: did.KeyMethod, KeyType: crypto.Ed25519})
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

		parsedCredential, err := signing.ParseVerifiableCredentialFromJWT(*createdCred.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredential)

		// make sure it has the right data
		assert.Equal(tt, issuer, parsedCredential.Issuer)
		assert.Equal(tt, subject, parsedCredential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
		assert.Equal(tt, "Satoshi", parsedCredential.CredentialSubject["firstName"])
		assert.Equal(tt, "Nakamoto", parsedCredential.CredentialSubject["lastName"])

		// get it back
		gotCred, err := credService.GetCredential(credential.GetCredentialRequest{ID: parsedCredential.ID})
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
		assert.Len(tt, bySchema.CredentialJWTs, 1)

		// parse cred
		parsedBySchema, err := signing.ParseVerifiableCredentialFromJWT(bySchema.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedBySchema)

		assert.Equal(tt, parsedCredential.ID, parsedBySchema.ID)
		assert.EqualValues(tt, parsedCredential.CredentialSchema, parsedBySchema.CredentialSchema)

		// get by subject
		bySubject, err := credService.GetCredentialsBySubject(credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.CredentialJWTs, 1)

		// parse cred
		parsedBySubject, err := signing.ParseVerifiableCredentialFromJWT(bySubject.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedBySubject)

		assert.Equal(tt, parsedCredential.ID, parsedBySubject.ID)
		assert.Equal(tt, parsedCredential.CredentialSubject[credsdk.VerifiableCredentialIDProperty], parsedBySubject.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// get by issuer
		byIssuer, err := credService.GetCredentialsByIssuer(credential.GetCredentialByIssuerRequest{Issuer: issuer})
		assert.NoError(tt, err)
		assert.Len(tt, byIssuer.CredentialJWTs, 1)

		// parse cred
		parsedByIssuer, err := signing.ParseVerifiableCredentialFromJWT(byIssuer.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedByIssuer)

		assert.Equal(tt, parsedCredential.ID, parsedByIssuer.ID)
		assert.Equal(tt, parsedCredential.Issuer, parsedByIssuer.Issuer)

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
		assert.Len(tt, byIssuer.CredentialJWTs, 2)

		// make sure the schema and subject queries are consistent
		bySchema, err = credService.GetCredentialsBySchema(credential.GetCredentialBySchemaRequest{Schema: ""})
		assert.NoError(tt, err)
		assert.Len(tt, bySchema.CredentialJWTs, 1)

		parsedBySchema, err = signing.ParseVerifiableCredentialFromJWT(bySchema.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedBySchema)

		assert.Equal(tt, parsedCredential.ID, parsedBySchema.ID)
		assert.EqualValues(tt, parsedCredential.CredentialSchema, parsedBySchema.CredentialSchema)

		bySubject, err = credService.GetCredentialsBySubject(credential.GetCredentialBySubjectRequest{Subject: subject})
		assert.NoError(tt, err)
		assert.Len(tt, bySubject.CredentialJWTs, 1)

		parsedBySubject, err = signing.ParseVerifiableCredentialFromJWT(bySubject.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedBySubject)

		assert.Equal(tt, parsedCredential.ID, parsedBySubject.ID)
		assert.Equal(tt, parsedCredential.CredentialSubject[credsdk.VerifiableCredentialIDProperty], parsedBySubject.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

		// delete a cred that doesn't exist (no error since idempotent)
		err = credService.DeleteCredential(credential.DeleteCredentialRequest{ID: "bad"})
		assert.NoError(tt, err)

		// delete a credential that does exist
		err = credService.DeleteCredential(credential.DeleteCredentialRequest{ID: parsedCredential.ID})
		assert.NoError(tt, err)

		// get it back
		_, err = credService.GetCredential(credential.GetCredentialRequest{ID: parsedCredential.ID})
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("credential not found with id: %s", parsedCredential.ID))
	})
}
