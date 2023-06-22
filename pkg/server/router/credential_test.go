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
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestCredentialRouter(t *testing.T) {

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {

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
				s := test.ServiceStorage(t)
				assert.NotEmpty(tt, s)

				serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential"}}
				keyStoreService := testKeyStoreService(tt, s)
				didService := testDIDService(tt, s, keyStoreService)
				schemaService := testSchemaService(tt, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					Data: map[string]any{
						"firstName": "Satoshi",
						"lastName":  "Nakamoto",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCred)
				assert.NotEmpty(tt, createdCred.CredentialJWT)
				assert.Empty(tt, createdCred.Credential.Evidence)

				cred := createdCred.Credential

				// make sure it has the right data
				assert.Equal(tt, issuer, cred.Issuer)
				assert.Equal(tt, subject, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
				assert.Equal(tt, "Satoshi", cred.CredentialSubject["firstName"])
				assert.Equal(tt, "Nakamoto", cred.CredentialSubject["lastName"])

				// get it back
				gotCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: idFromURI(cred.ID)})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, gotCred)

				// compare for object equality
				assert.Equal(tt, createdCred.CredentialJWT, gotCred.CredentialJWT)

				// verify it
				verified, err := credService.VerifyCredential(context.Background(), credential.VerifyCredentialRequest{CredentialJWT: gotCred.CredentialJWT})
				assert.NoError(tt, err)
				assert.True(tt, verified.Verified)

				// get a cred that doesn't exist
				_, err = credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: "bad"})
				assert.Error(tt, err)
				assert.Contains(tt, err.Error(), "credential not found with id: bad")

				// get by schema - no schema
				bySchema, err := credService.ListCredentialsBySchema(context.Background(), credential.ListCredentialBySchemaRequest{Schema: ""})
				assert.NoError(tt, err)
				assert.Len(tt, bySchema.Credentials, 1)
				assert.EqualValues(tt, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

				// get by subject
				bySubject, err := credService.ListCredentialsBySubject(context.Background(), credential.ListCredentialBySubjectRequest{Subject: subject})
				assert.NoError(tt, err)
				assert.Len(tt, bySubject.Credentials, 1)

				assert.Equal(tt, cred.ID, bySubject.Credentials[0].ID)
				assert.Equal(tt, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

				// get by issuer
				byIssuer, err := credService.ListCredentialsByIssuer(context.Background(), credential.ListCredentialByIssuerRequest{Issuer: issuer})
				assert.NoError(tt, err)
				assert.Len(tt, byIssuer.Credentials, 1)

				assert.Equal(tt, cred.ID, byIssuer.Credentials[0].Credential.ID)
				assert.Equal(tt, cred.Issuer, byIssuer.Credentials[0].Credential.Issuer)

				// create another cred with the same issuer, different subject, different schema that doesn't exist
				_, err = credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   "did:abcd:efghi",
					SchemaID:  "https://test-schema.com",
					Data: map[string]any{
						"email": "satoshi@nakamoto.com",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.Error(tt, err)
				assert.Contains(tt, err.Error(), "schema not found with id: https://test-schema.com")

				// create schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)

				// create another cred with the same issuer, different subject, different schema that does exist
				createdCredWithSchema, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   "did:abcd:efghi",
					SchemaID:  createdSchema.ID,
					Data: map[string]any{
						"email": "satoshi@nakamoto.com",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCredWithSchema)

				// get by issuer
				byIssuer, err = credService.ListCredentialsByIssuer(context.Background(), credential.ListCredentialByIssuerRequest{Issuer: issuer})
				assert.NoError(tt, err)
				assert.Len(tt, byIssuer.Credentials, 2)

				// make sure the schema and subject queries are consistent
				bySchema, err = credService.ListCredentialsBySchema(context.Background(), credential.ListCredentialBySchemaRequest{Schema: ""})
				assert.NoError(tt, err)
				assert.Len(tt, bySchema.Credentials, 1)

				assert.Equal(tt, cred.ID, bySchema.Credentials[0].ID)
				assert.EqualValues(tt, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

				bySubject, err = credService.ListCredentialsBySubject(context.Background(), credential.ListCredentialBySubjectRequest{Subject: subject})
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
				s := test.ServiceStorage(t)
				assert.NotEmpty(tt, s)

				serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "v1/credentials"}}
				keyStoreService := testKeyStoreService(tt, s)
				didService := testDIDService(tt, s, keyStoreService)
				schemaService := testSchemaService(tt, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
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

				assert.Equal(tt, credStatusMap["id"], createdCred.ID+"/status")
				assert.Contains(tt, credStatusMap["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(tt, credStatusMap["statusListIndex"])

				createdCredTwo, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
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

				assert.Equal(tt, credStatusMapTwo["id"], createdCredTwo.ID+"/status")
				assert.Contains(tt, credStatusMapTwo["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(tt, credStatusMapTwo["statusListIndex"])

				// Cred with same <issuer, schema> pair share the same statusListCredential
				assert.Equal(tt, credStatusMapTwo["statusListCredential"], credStatusMap["statusListCredential"])

				createdSchemaTwo, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchemaTwo)

				createdCredThree, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchemaTwo.ID,
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

				assert.Contains(tt, credStatusMapThree["id"], createdCredThree.ID)
				assert.Contains(tt, credStatusMapThree["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(tt, credStatusMapThree["statusListIndex"])

				// Cred with different <issuer, schema> pair have different statusListCredential
				assert.NotEqual(tt, credStatusMapThree["statusListCredential"], credStatusMap["statusListCredential"])
			})

			t.Run("Credential Status List Test No Schemas", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(tt, s)

				serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "/v1/credentials"}}
				keyStoreService := testKeyStoreService(tt, s)
				didService := testDIDService(tt, s, keyStoreService)
				schemaService := testSchemaService(tt, s, keyStoreService, didService)

				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
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

				assert.Contains(tt, credStatusMap["id"], fmt.Sprintf("%s/status", createdCred.ID))
				assert.Contains(tt, credStatusMap["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(tt, credStatusMap["statusListIndex"])

				createdCredTwo, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
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

				assert.Contains(tt, credStatusMapTwo["id"], fmt.Sprintf("%s/status", createdCredTwo.ID))
				assert.Contains(tt, credStatusMapTwo["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(tt, credStatusMapTwo["statusListIndex"])

				// Cred with same <issuer, schema> pair share the same statusListCredential
				assert.Equal(tt, credStatusMapTwo["statusListCredential"], credStatusMap["statusListCredential"])

				// create schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)

				createdCredThree, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
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

				assert.Contains(tt, credStatusMapThree["id"], fmt.Sprintf("%s/status", createdCredThree.ID))
				assert.Contains(tt, credStatusMapThree["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(tt, credStatusMapThree["statusListIndex"])

				// Cred with different <issuer, schema> pair have different statusListCredential
				assert.NotEqual(tt, credStatusMapThree["statusListCredential"], credStatusMap["statusListCredential"])
			})

			t.Run("Credential Status List Test Update Revoked Status", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(tt, s)

				serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "http://localhost:1234/v1/credentials"}}
				keyStoreService := testKeyStoreService(tt, s)
				didService := testDIDService(tt, s, keyStoreService)
				schemaService := testSchemaService(tt, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				nonRevokableCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
					Data: map[string]any{
						"email": "cant@revoke.me",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(tt, err)

				_, err = credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(nonRevokableCred.ID), Revoked: true})
				assert.ErrorContains(tt, err, "has no credentialStatus field")

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
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

				assert.Contains(tt, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.ID))
				assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
				assert.NotEmpty(tt, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, credStatus.Revoked, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(tt, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Revoked: true})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedStatus.Revoked, true)

				updatedCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedCred.Revoked, true)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

			t.Run("Credential Status List Test Update Suspended Status", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(tt, s)

				serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "http://localhost:1234/v1/credentials"}}
				keyStoreService := testKeyStoreService(tt, s)
				didService := testDIDService(tt, s, keyStoreService)
				schemaService := testSchemaService(tt, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				nonSuspendableCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
					Data: map[string]any{
						"email": "cant@revoke.me",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(tt, err)

				_, err = credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(nonSuspendableCred.ID), Suspended: true})
				assert.ErrorContains(tt, err, "has no credentialStatus field")

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
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

				assert.Contains(tt, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.ID))
				assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
				assert.NotEmpty(tt, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(tt, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Suspended: true})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedStatus.Suspended, true)

				updatedCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedCred.Suspended, true)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

			t.Run("Create Multiple Suspendable Credential Different IssuerDID SchemaID StatusPurpose Triples", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(tt, s)

				serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "http://localhost:1234/v1/credentials"}}
				keyStoreService := testKeyStoreService(tt, s)
				didService := testDIDService(tt, s, keyStoreService)
				schemaService := testSchemaService(tt, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdSchema)

				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuerDID.DID.ID,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCred)

				createdCredSuspendable, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuerDID.DID.ID,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   subject,
					SchemaID:  createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})
				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCredSuspendable)

				revocationKey := strings.Join([]string{"is:" + issuerDID.DID.ID, "sc:" + createdSchema.ID, "sp:" + string(status.StatusRevocation)}, "-")

				slcExists, err := s.Exists(context.Background(), "status-list-credential", revocationKey)
				assert.NoError(tt, err)
				assert.True(tt, slcExists)

				indexPoolExists, err := s.Exists(context.Background(), "status-list-index-pool", revocationKey)
				assert.NoError(tt, err)
				assert.True(tt, indexPoolExists)

				currentIndexExists, err := s.Exists(context.Background(), "status-list-current-index", revocationKey)
				assert.NoError(tt, err)
				assert.True(tt, currentIndexExists)

				suspensionKey := strings.Join([]string{"is:" + issuerDID.DID.ID, "sc:" + createdSchema.ID, "sp:" + string(status.StatusSuspension)}, "-")

				slcExists, err = s.Exists(context.Background(), "status-list-credential", suspensionKey)
				assert.NoError(tt, err)
				assert.True(tt, slcExists)

				indexPoolExists, err = s.Exists(context.Background(), "status-list-index-pool", suspensionKey)
				assert.NoError(tt, err)
				assert.True(tt, indexPoolExists)

				currentIndexExists, err = s.Exists(context.Background(), "status-list-current-index", suspensionKey)
				assert.NoError(tt, err)
				assert.True(tt, currentIndexExists)
			})

			t.Run("Create Suspendable Credential", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
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

				assert.Contains(tt, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.ID))
				assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
				assert.NotEmpty(tt, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, credStatus.Revoked, false)
				assert.Equal(tt, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(tt, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
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

				assert.Contains(tt, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.ID))
				assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
				assert.NotEmpty(tt, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, credStatus.Revoked, false)
				assert.Equal(tt, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(tt, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Suspended: true})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedStatus.Suspended, true)
				assert.Equal(tt, updatedStatus.Revoked, false)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

			t.Run("Update Suspendable Credential To Suspended then Unsuspended", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
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

				assert.Contains(tt, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.ID))
				assert.Contains(tt, statusEntry.StatusListCredential, "http://localhost:1234/v1/credentials/status")
				assert.NotEmpty(tt, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: idFromURI(createdCred.ID)})
				assert.NoError(tt, err)
				assert.Equal(tt, credStatus.Revoked, false)
				assert.Equal(tt, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(tt, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Suspended: true})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedStatus.Suspended, true)
				assert.Equal(tt, updatedStatus.Revoked, false)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
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

				updatedStatus, err = credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Suspended: false})
				assert.NoError(tt, err)
				assert.Equal(tt, updatedStatus.Suspended, false)
				assert.Equal(tt, updatedStatus.Revoked, false)
			})

			t.Run("Create Suspendable and Revocable Credential Should Be Error", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
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
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})

				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCred)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Revoked: true, Suspended: true})
				assert.Nil(tt, updatedStatus)
				assert.Error(tt, err)
				assert.ErrorContains(tt, err, "cannot update both suspended and revoked status")
			})

			t.Run("Update Suspended On Revoked Credential Should Be Error", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCred)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: idFromURI(createdCred.ID), Suspended: true})
				assert.Nil(tt, updatedStatus)
				assert.Error(tt, err)
				assert.ErrorContains(tt, err, "has a different status purpose<revocation> value than the status credential<suspension>")
			})

			t.Run("Create Credential With Invalid Evidence", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				_, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Evidence: []any{"hi", 123, true},
				})

				assert.ErrorContains(tt, err, "invalid evidence format")
			})

			t.Run("Create Credential With Invalid Evidence No Id", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				evidenceMap := map[string]any{
					"type":             []string{"DocumentVerification"},
					"verifier":         "https://example.edu/issuers/14",
					"evidenceDocument": "DriversLicense",
					"subjectPresence":  "Physical",
					"documentPresence": "Physical",
					"licenseNumber":    "123AB4567",
				}

				_, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Evidence: []any{evidenceMap},
				})

				assert.ErrorContains(tt, err, "missing required 'id' or 'type'")
			})

			t.Run("Create Credential With Evidence", func(tt *testing.T) {
				issuer, issuerKID, schemaID, credService := createCredServicePrereqs(tt, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:    issuer,
					IssuerKID: issuerKID,
					Subject:   subject,
					SchemaID:  schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Evidence: getEvidence(),
				})

				assert.NoError(tt, err)
				assert.NotEmpty(tt, createdCred)
				assert.NotEmpty(tt, createdCred.CredentialJWT)

				assert.ElementsMatch(tt, createdCred.Credential.Evidence, getEvidence())
			})
		})
	}
}

func idFromURI(cred string) string {
	return cred[len(cred)-36:]
}

func createCredServicePrereqs(tt *testing.T, s storage.ServiceStorage) (issuer, issuerKID, schemaID string, credSvc credential.Service) {
	require.NotEmpty(tt, s)

	serviceConfig := config.CredentialServiceConfig{BaseServiceConfig: &config.BaseServiceConfig{Name: "credential", ServiceEndpoint: "http://localhost:1234/v1/credentials"}}
	keyStoreService := testKeyStoreService(tt, s)
	didService := testDIDService(tt, s, keyStoreService)
	schemaService := testSchemaService(tt, s, keyStoreService, didService)
	credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
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
	createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
	require.NoError(tt, err)
	require.NotEmpty(tt, createdSchema)

	return issuerDID.DID.ID, issuerDID.DID.VerificationMethod[0].ID, createdSchema.ID, *credService
}

func getEmailSchema() map[string]any {
	return map[string]any{
		"$schema": "https://json-schema.org/draft-07/schema",
		"type":    "object",
		"properties": map[string]any{
			"credentialSubject": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"email": map[string]any{
						"type": "string",
					},
				},
				"required": []any{"email"},
			},
		},
	}
}

func getEvidence() []any {
	evidenceMap := map[string]any{
		"id":               "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
		"type":             []string{"DocumentVerification"},
		"verifier":         "https://example.edu/issuers/14",
		"evidenceDocument": "DriversLicense",
		"subjectPresence":  "Physical",
		"documentPresence": "Physical",
		"licenseNumber":    "123AB4567",
	}
	return []any{evidenceMap}
}
