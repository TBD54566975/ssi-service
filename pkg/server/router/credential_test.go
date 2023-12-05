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
	"github.com/tbd54566975/ssi-service/pkg/server/pagination"
	"github.com/tbd54566975/ssi-service/pkg/service/credential"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/keystore"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
	"go.einride.tech/aip/filtering"
)

func TestCredentialRouter(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {

			t.Run("Nil Service", func(t *testing.T) {
				credRouter, err := NewCredentialRouter(nil)
				assert.Error(t, err)
				assert.Empty(t, credRouter)
				assert.Contains(t, err.Error(), "service cannot be nil")
			})

			t.Run("Bad Service", func(t *testing.T) {
				credRouter, err := NewCredentialRouter(&testService{})
				assert.Error(t, err)
				assert.Empty(t, credRouter)
				assert.Contains(t, err.Error(), "could not create credential router with service type: test")
			})

			t.Run("Credential Service Test", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)

				// check type and status
				assert.Equal(t, framework.Credential, credService.Type())
				assert.Equal(t, framework.StatusReady, credService.Status().Status)

				// create a credential

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"
				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					Data: map[string]any{
						"firstName": "Satoshi",
						"lastName":  "Nakamoto",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)
				assert.Empty(t, createdCred.Credential.Evidence)

				cred := createdCred.Credential

				// make sure it has the right data
				assert.Equal(t, issuer, cred.Issuer)
				assert.Equal(t, subject, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
				assert.Equal(t, "Satoshi", cred.CredentialSubject["firstName"])
				assert.Equal(t, "Nakamoto", cred.CredentialSubject["lastName"])

				// get it back
				gotCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: idFromURI(cred.ID)})
				assert.NoError(t, err)
				assert.NotEmpty(t, gotCred)

				// compare for object equality
				assert.Equal(t, createdCred.CredentialJWT, gotCred.CredentialJWT)

				// verify it
				verified, err := credService.VerifyCredential(context.Background(), credential.VerifyCredentialRequest{CredentialJWT: gotCred.CredentialJWT})
				assert.NoError(t, err)
				assert.True(t, verified.Verified)

				// get a cred that doesn't exist
				_, err = credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: "bad"})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "credential not found with id: bad")

				// get by schema - no schema
				sch := ""
				filter, err := filtering.ParseFilter(listCredentialsRequest{schema: &sch}, listCredentialsFilterDeclarations)
				assert.NoError(t, err)
				bySchema, err := credService.ListCredentials(context.Background(), filter, pagination.PageRequest{})
				assert.NoError(t, err)
				assert.Len(t, bySchema.Credentials, 1)
				assert.EqualValues(t, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

				// get by subject
				filter, err = filtering.ParseFilter(listCredentialsRequest{subject: &subject}, listCredentialsFilterDeclarations)
				assert.NoError(t, err)
				bySubject, err := credService.ListCredentials(context.Background(), filter, pagination.PageRequest{})
				assert.NoError(t, err)
				assert.Len(t, bySubject.Credentials, 1)

				assert.Equal(t, createdCred.ID, bySubject.Credentials[0].ID)
				assert.Equal(t, cred.ID, bySubject.Credentials[0].Credential.ID)
				assert.Equal(t, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

				// get by issuer
				filter, err = filtering.ParseFilter(listCredentialsRequest{issuer: &issuer}, listCredentialsFilterDeclarations)
				assert.NoError(t, err)
				byIssuer, err := credService.ListCredentials(context.Background(), filter, pagination.PageRequest{})
				assert.NoError(t, err)
				assert.Len(t, byIssuer.Credentials, 1)

				assert.Equal(t, cred.ID, byIssuer.Credentials[0].Credential.ID)
				assert.Equal(t, cred.Issuer, byIssuer.Credentials[0].Credential.Issuer)

				// create another cred with the same issuer, different subject, different schema that doesn't exist
				_, err = credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            "did:abcd:efghi",
					SchemaID:                           "https://test-schema.com",
					Data: map[string]any{
						"email": "satoshi@nakamoto.com",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "schema not found with id: https://test-schema.com")

				// create schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				// create another cred with the same issuer, different subject, different schema that does exist
				createdCredWithSchema, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            "did:abcd:efghi",
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "satoshi@nakamoto.com",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredWithSchema)

				// get by issuer
				byIssuer, err = credService.ListCredentials(context.Background(), filter, pagination.PageRequest{})
				assert.NoError(t, err)
				assert.Len(t, byIssuer.Credentials, 2)

				// make sure the schema and subject queries are consistent
				filter, err = filtering.ParseFilter(listCredentialsRequest{schema: &sch}, listCredentialsFilterDeclarations)
				assert.NoError(t, err)
				bySchema, err = credService.ListCredentials(context.Background(), filter, pagination.PageRequest{})
				assert.NoError(t, err)
				assert.Len(t, bySchema.Credentials, 1)

				assert.Equal(t, createdCred.ID, bySchema.Credentials[0].ID)
				assert.Equal(t, cred.ID, bySchema.Credentials[0].Credential.ID)
				assert.EqualValues(t, cred.CredentialSchema, bySchema.Credentials[0].Credential.CredentialSchema)

				filter, err = filtering.ParseFilter(listCredentialsRequest{subject: &subject}, listCredentialsFilterDeclarations)
				assert.NoError(t, err)
				bySubject, err = credService.ListCredentials(context.Background(), filter, pagination.PageRequest{})
				assert.NoError(t, err)
				assert.Len(t, bySubject.Credentials, 1)

				assert.Equal(t, createdCred.ID, bySubject.Credentials[0].ID)
				assert.Equal(t, cred.ID, bySubject.Credentials[0].Credential.ID)
				assert.Equal(t, cred.CredentialSubject[credsdk.VerifiableCredentialIDProperty], bySubject.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])

				// delete a cred that doesn't exist (no error since idempotent)
				err = credService.DeleteCredential(context.Background(), credential.DeleteCredentialRequest{ID: "bad"})
				assert.NoError(t, err)

				// delete a credential that does exist
				err = credService.DeleteCredential(context.Background(), credential.DeleteCredentialRequest{ID: cred.ID})
				assert.NoError(t, err)

				// get it back
				_, err = credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: cred.ID})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), fmt.Sprintf("credential not found with id: %s", cred.ID))
			})

			t.Run("Credential Service Test Revoked Key", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				// Initialize services
				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)

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

				// Create a crendential
				subject := "did:test:42"
				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             didID,
					FullyQualifiedVerificationMethodID: keyID,
					Subject:                            subject,
					Data: map[string]any{
						"firstName": "Satoshi",
						"lastName":  "Nakamoto",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				// Revoke the key
				err = keyStoreService.RevokeKey(context.Background(), keystore.RevokeKeyRequest{ID: keyID})
				assert.NoError(t, err)

				// Create a credential with the revoked key, it fails
				subject = "did:test:43"
				createdCred, err = credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             didID,
					FullyQualifiedVerificationMethodID: keyID,
					Subject:                            subject,
					Data: map[string]any{
						"firstName": "John",
						"lastName":  "Doe",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.Empty(t, createdCred)
				assert.Error(t, err)
				assert.ErrorContains(t, err, "cannot use revoked key")
			})

			t.Run("Credential Status List Test", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)

				// check type and status
				assert.Equal(t, framework.Credential, credService.Type())
				assert.Equal(t, framework.StatusReady, credService.Status().Status)

				// create a did
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				createdCredResp, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredResp)
				assert.NotEmpty(t, createdCredResp.CredentialJWT)

				credStatusMap, ok := createdCredResp.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.Equal(t, credStatusMap["id"], createdCredResp.Credential.ID+"/status")
				assert.Contains(t, credStatusMap["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				createdCredRespTwo, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi2@Nakamoto2.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredRespTwo)
				assert.NotEmpty(t, createdCredRespTwo.CredentialJWT)

				credStatusMapTwo, ok := createdCredRespTwo.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.Equal(t, credStatusMapTwo["id"], createdCredRespTwo.Credential.ID+"/status")
				assert.Contains(t, credStatusMapTwo["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(t, credStatusMapTwo["statusListIndex"])

				// Cred with same <issuer, schema> pair share the same statusListCredential
				assert.Equal(t, credStatusMapTwo["statusListCredential"], credStatusMap["statusListCredential"])

				createdSchemaTwo, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchemaTwo)

				createdCredRespThree, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchemaTwo.ID,
					Data: map[string]any{
						"email": "Satoshi2@Nakamoto2.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredRespThree)
				assert.NotEmpty(t, createdCredRespThree.CredentialJWT)

				credStatusMapThree, ok := createdCredRespThree.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.Contains(t, credStatusMapThree["id"], createdCredRespThree.Credential.ID)
				assert.Contains(t, credStatusMapThree["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(t, credStatusMapThree["statusListIndex"])

				// Cred with different <issuer, schema> pair have different statusListCredential
				assert.NotEqual(t, credStatusMapThree["statusListCredential"], credStatusMap["statusListCredential"])
			})

			t.Run("Credential Status List Test No Schemas", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)

				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)

				// check type and status
				assert.Equal(t, framework.Credential, credService.Type())
				assert.Equal(t, framework.StatusReady, credService.Status().Status)

				// create a did
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				createdCredResp, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredResp)
				assert.NotEmpty(t, createdCredResp.CredentialJWT)

				credStatusMap, ok := createdCredResp.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.Contains(t, credStatusMap["id"], fmt.Sprintf("%s/status", createdCredResp.Credential.ID))
				assert.Contains(t, credStatusMap["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				createdCredRespTwo, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					Data: map[string]any{
						"email": "Satoshi2@Nakamoto2.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredRespTwo)
				assert.NotEmpty(t, createdCredRespTwo.CredentialJWT)

				credStatusMapTwo, ok := createdCredRespTwo.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.Contains(t, credStatusMapTwo["id"], fmt.Sprintf("%s/status", createdCredRespTwo.Credential.ID))
				assert.Contains(t, credStatusMapTwo["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(t, credStatusMapTwo["statusListIndex"])

				// Cred with same <issuer, schema> pair share the same statusListCredential
				assert.Equal(t, credStatusMapTwo["statusListCredential"], credStatusMap["statusListCredential"])

				// create schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				createdCredRespThree, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi2@Nakamoto2.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredRespThree)
				assert.NotEmpty(t, createdCredRespThree.CredentialJWT)

				credStatusMapThree, ok := createdCredRespThree.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.Contains(t, credStatusMapThree["id"], fmt.Sprintf("%s/status", createdCredRespThree.Credential.ID))
				assert.Contains(t, credStatusMapThree["statusListCredential"], "v1/credentials/status")
				assert.NotEmpty(t, credStatusMapThree["statusListIndex"])

				// Cred with different <issuer, schema> pair have different statusListCredential
				assert.NotEqual(t, credStatusMapThree["statusListCredential"], credStatusMap["statusListCredential"])
			})

			t.Run("Credential Status List Test Update Revoked Status", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)
				// check type and status
				assert.Equal(t, framework.Credential, credService.Type())
				assert.Equal(t, framework.StatusReady, credService.Status().Status)

				// create a did
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				nonRevokableCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "cant@revoke.me",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(t, err)

				_, err = credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: nonRevokableCred.ID, Revoked: true})
				assert.ErrorContains(t, err, "has no credentialStatus field")

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
				assert.NoError(t, err)

				var statusEntry status.StatusList2021Entry
				err = json.Unmarshal(statusBytes, &statusEntry)
				assert.NoError(t, err)

				assert.Contains(t, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.Credential.ID))
				assert.Contains(t, statusEntry.StatusListCredential, "https://ssi-service.com/v1/credentials/status")
				assert.NotEmpty(t, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, credStatus.Revoked, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(t, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusList.Credential.ID, statusEntry.StatusListCredential)

				credentialSubject := credStatusList.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubject)

				encodedList := credentialSubject["encodedList"]
				assert.NotEmpty(t, encodedList)

				// Validate the StatusListIndex is not flipped in the credStatusList
				valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
				assert.NoError(t, err)
				assert.False(t, valid)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Revoked: true})
				assert.NoError(t, err)
				assert.Equal(t, updatedStatus.Revoked, true)

				updatedCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, updatedCred.Revoked, true)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: credStatusListID})
				assert.NoError(t, err)
				assert.Equal(t, credStatusListAfterRevoke.Credential.ID, statusEntry.StatusListCredential)

				// Validate the StatusListIndex in flipped in the credStatusList
				valid, err = status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusListAfterRevoke.Credential)
				assert.NoError(t, err)
				assert.True(t, valid)

				credentialSubjectAfterRevoke := credStatusListAfterRevoke.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubjectAfterRevoke)

				encodedListAfterRevoke := credentialSubjectAfterRevoke["encodedList"]
				assert.NotEmpty(t, encodedListAfterRevoke)

				assert.NotEqualValues(t, encodedListAfterRevoke, encodedList)

			})

			t.Run("Credential Status List Test Update Suspended Status", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)
				// check type and status
				assert.Equal(t, framework.Credential, credService.Type())
				assert.Equal(t, framework.StatusReady, credService.Status().Status)

				// create a did
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				issuer := issuerDID.DID.ID
				subject := "did:test:345"

				nonSuspendableCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "cant@revoke.me",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				})
				assert.NoError(t, err)

				_, err = credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: nonSuspendableCred.ID, Suspended: true})
				assert.ErrorContains(t, err, "has no credentialStatus field")

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
				assert.NoError(t, err)

				var statusEntry status.StatusList2021Entry
				err = json.Unmarshal(statusBytes, &statusEntry)
				assert.NoError(t, err)

				assert.Contains(t, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.Credential.ID))
				assert.Contains(t, statusEntry.StatusListCredential, "https://ssi-service.com/v1/credentials/status")
				assert.NotEmpty(t, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(t, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusList.Credential.ID, statusEntry.StatusListCredential)

				credentialSubject := credStatusList.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubject)

				encodedList := credentialSubject["encodedList"]
				assert.NotEmpty(t, encodedList)

				// Validate the StatusListIndex is not flipped in the credStatusList
				valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
				assert.NoError(t, err)
				assert.False(t, valid)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: true})
				assert.NoError(t, err)
				assert.Equal(t, updatedStatus.Suspended, true)

				updatedCred, err := credService.GetCredential(context.Background(), credential.GetCredentialRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, updatedCred.Suspended, true)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusListAfterRevoke.Credential.ID, statusEntry.StatusListCredential)

				// Validate the StatusListIndex in flipped in the credStatusList
				valid, err = status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusListAfterRevoke.Credential)
				assert.NoError(t, err)
				assert.True(t, valid)

				credentialSubjectAfterRevoke := credStatusListAfterRevoke.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubjectAfterRevoke)

				encodedListAfterRevoke := credentialSubjectAfterRevoke["encodedList"]
				assert.NotEmpty(t, encodedListAfterRevoke)

				assert.NotEqualValues(t, encodedListAfterRevoke, encodedList)

			})

			t.Run("Create Multiple Suspendable Credential Different IssuerDID SchemaID StatusPurpose Triples", func(t *testing.T) {
				s := test.ServiceStorage(t)
				assert.NotEmpty(t, s)

				serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
				keyStoreService := testKeyStoreService(t, s)
				didService := testDIDService(t, s, keyStoreService)
				schemaService := testSchemaService(t, s, keyStoreService, didService)
				credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
				assert.NoError(t, err)
				assert.NotEmpty(t, credService)
				// check type and status
				assert.Equal(t, framework.Credential, credService.Type())
				assert.Equal(t, framework.StatusReady, credService.Status().Status)

				// create a did
				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// create a schema
				createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuerDID.DID.ID,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				createdCredSuspendable, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuerDID.DID.ID,
					FullyQualifiedVerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:                            subject,
					SchemaID:                           createdSchema.ID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, createdCredSuspendable)

				revocationKey := storage.Join("is", issuerDID.DID.ID, "sc", createdSchema.ID, "sp", string(status.StatusRevocation))

				slcExists, err := s.Exists(context.Background(), "status-list-credential", revocationKey)
				assert.NoError(t, err)
				assert.True(t, slcExists)

				indexPoolExists, err := s.Exists(context.Background(), "status-list-index-pool", revocationKey)
				assert.NoError(t, err)
				assert.True(t, indexPoolExists)

				currentIndexExists, err := s.Exists(context.Background(), "status-list-current-index", revocationKey)
				assert.NoError(t, err)
				assert.True(t, currentIndexExists)

				suspensionKey := storage.Join("is", issuerDID.DID.ID, "sc", createdSchema.ID, "sp", string(status.StatusSuspension))

				slcExists, err = s.Exists(context.Background(), "status-list-credential", suspensionKey)
				assert.NoError(t, err)
				assert.True(t, slcExists)

				indexPoolExists, err = s.Exists(context.Background(), "status-list-index-pool", suspensionKey)
				assert.NoError(t, err)
				assert.True(t, indexPoolExists)

				currentIndexExists, err = s.Exists(context.Background(), "status-list-current-index", suspensionKey)
				assert.NoError(t, err)
				assert.True(t, currentIndexExists)
			})

			t.Run("Create Suspendable Credential", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
				assert.NoError(t, err)

				var statusEntry status.StatusList2021Entry
				err = json.Unmarshal(statusBytes, &statusEntry)
				assert.NoError(t, err)

				assert.Contains(t, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.Credential.ID))
				assert.Contains(t, statusEntry.StatusListCredential, "https://ssi-service.com/v1/credentials/status")
				assert.NotEmpty(t, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, credStatus.Revoked, false)
				assert.Equal(t, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(t, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusList.Credential.ID, statusEntry.StatusListCredential)

				credentialSubject := credStatusList.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubject)

				encodedList := credentialSubject["encodedList"]
				assert.NotEmpty(t, encodedList)

				// Validate the StatusListIndex is not flipped in the credStatusList
				valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
				assert.NoError(t, err)
				assert.False(t, valid)
			})

			t.Run("Update Suspendable Credential To Suspended", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
				assert.NoError(t, err)

				var statusEntry status.StatusList2021Entry
				err = json.Unmarshal(statusBytes, &statusEntry)
				assert.NoError(t, err)

				assert.Contains(t, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.Credential.ID))
				assert.Contains(t, statusEntry.StatusListCredential, "https://ssi-service.com/v1/credentials/status")
				assert.NotEmpty(t, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, credStatus.Revoked, false)
				assert.Equal(t, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(t, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusList.Credential.ID, statusEntry.StatusListCredential)

				credentialSubject := credStatusList.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubject)

				encodedList := credentialSubject["encodedList"]
				assert.NotEmpty(t, encodedList)

				// Validate the StatusListIndex is not flipped in the credStatusList
				valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
				assert.NoError(t, err)
				assert.False(t, valid)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: true})
				assert.NoError(t, err)
				assert.Equal(t, updatedStatus.Suspended, true)
				assert.Equal(t, updatedStatus.Revoked, false)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusListAfterRevoke.Credential.ID, statusEntry.StatusListCredential)

				// Validate the StatusListIndex in flipped in the credStatusList
				valid, err = status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusListAfterRevoke.Credential)
				assert.NoError(t, err)
				assert.True(t, valid)

				credentialSubjectAfterRevoke := credStatusListAfterRevoke.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubjectAfterRevoke)

				encodedListAfterSuspended := credentialSubjectAfterRevoke["encodedList"]
				assert.NotEmpty(t, encodedListAfterSuspended)

				assert.NotEqualValues(t, encodedListAfterSuspended, encodedList)
			})

			t.Run("Update Suspendable Credential To Suspended then Unsuspended", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				statusBytes, err := json.Marshal(createdCred.Credential.CredentialStatus)
				assert.NoError(t, err)

				var statusEntry status.StatusList2021Entry
				err = json.Unmarshal(statusBytes, &statusEntry)
				assert.NoError(t, err)

				assert.Contains(t, statusEntry.ID, fmt.Sprintf("%s/status", createdCred.Credential.ID))
				assert.Contains(t, statusEntry.StatusListCredential, "https://ssi-service.com/v1/credentials/status")
				assert.NotEmpty(t, statusEntry.StatusListIndex)

				credStatus, err := credService.GetCredentialStatus(context.Background(), credential.GetCredentialStatusRequest{ID: createdCred.ID})
				assert.NoError(t, err)
				assert.Equal(t, credStatus.Revoked, false)
				assert.Equal(t, credStatus.Suspended, false)

				credStatusListStr := statusEntry.StatusListCredential

				_, credStatusListID, ok := strings.Cut(credStatusListStr, "/v1/credentials/status/")
				assert.True(t, ok)
				credStatusList, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusList.Credential.ID, statusEntry.StatusListCredential)

				credentialSubject := credStatusList.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubject)

				encodedList := credentialSubject["encodedList"]
				assert.NotEmpty(t, encodedList)

				// Validate the StatusListIndex is not flipped in the credStatusList
				valid, err := status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusList.Credential)
				assert.NoError(t, err)
				assert.False(t, valid)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: true})
				assert.NoError(t, err)
				assert.Equal(t, updatedStatus.Suspended, true)
				assert.Equal(t, updatedStatus.Revoked, false)

				credStatusListAfterRevoke, err := credService.GetCredentialStatusList(context.Background(), credential.GetCredentialStatusListRequest{ID: idFromURI(credStatusListID)})
				assert.NoError(t, err)
				assert.Equal(t, credStatusListAfterRevoke.Credential.ID, statusEntry.StatusListCredential)

				// Validate the StatusListIndex in flipped in the credStatusList
				valid, err = status.ValidateCredentialInStatusList(*createdCred.Credential, *credStatusListAfterRevoke.Credential)
				assert.NoError(t, err)
				assert.True(t, valid)

				credentialSubjectAfterRevoke := credStatusListAfterRevoke.Container.Credential.CredentialSubject
				assert.NotEmpty(t, credentialSubjectAfterRevoke)

				encodedListAfterSuspended := credentialSubjectAfterRevoke["encodedList"]
				assert.NotEmpty(t, encodedListAfterSuspended)

				assert.NotEqualValues(t, encodedListAfterSuspended, encodedList)

				updatedStatus, err = credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: false})
				assert.NoError(t, err)
				assert.Equal(t, updatedStatus.Suspended, false)
				assert.Equal(t, updatedStatus.Revoked, false)
			})

			t.Run("Create Suspendable and Revocable Credential Should Be Error", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable:   true,
					Suspendable: true,
				})

				assert.Error(t, err)
				assert.ErrorContains(t, err, "credential may have at most one status")
				assert.Empty(t, createdCred)
			})

			t.Run("Update Suspendable and Revocable Credential Should Be Error", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Suspendable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Revoked: true, Suspended: true})
				assert.Nil(t, updatedStatus)
				assert.Error(t, err)
				assert.ErrorContains(t, err, "cannot update both suspended and revoked status")
			})

			t.Run("Update Suspended On Revoked Credential Should Be Error", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)

				updatedStatus, err := credService.UpdateCredentialStatus(context.Background(), credential.UpdateCredentialStatusRequest{ID: createdCred.ID, Suspended: true})
				assert.Nil(t, updatedStatus)
				assert.Error(t, err)
				assert.ErrorContains(t, err, "has a different status purpose<revocation> value than the status credential<suspension>")
			})

			t.Run("Create Credential With Invalid Evidence", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				_, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Evidence: []any{"hi", 123, true},
				})

				assert.ErrorContains(t, err, "invalid evidence format")
			})

			t.Run("Create Credential With Invalid Evidence No Id", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
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
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Evidence: []any{evidenceMap},
				})

				assert.ErrorContains(t, err, "missing required 'id' or 'type'")
			})

			t.Run("Create Credential With Evidence", func(t *testing.T) {
				issuer, verificationMethodID, schemaID, credService := createCredServicePrereqs(t, test.ServiceStorage(t))
				subject := "did:test:345"

				createdCred, err := credService.CreateCredential(context.Background(), credential.CreateCredentialRequest{
					Issuer:                             issuer,
					FullyQualifiedVerificationMethodID: verificationMethodID,
					Subject:                            subject,
					SchemaID:                           schemaID,
					Data: map[string]any{
						"email": "Satoshi@Nakamoto.btc",
					},
					Expiry:   time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Evidence: getEvidence(),
				})

				assert.NoError(t, err)
				assert.NotEmpty(t, createdCred)
				assert.NotEmpty(t, createdCred.CredentialJWT)

				assert.ElementsMatch(t, createdCred.Credential.Evidence, getEvidence())
			})
		})
	}
}

func idFromURI(cred string) string {
	return cred[len(cred)-36:]
}

func createCredServicePrereqs(t *testing.T, s storage.ServiceStorage) (issuer, verificationMethodID, schemaID string, credSvc credential.Service) {
	require.NotEmpty(t, s)

	serviceConfig := config.CredentialServiceConfig{BatchCreateMaxItems: 100}
	keyStoreService := testKeyStoreService(t, s)
	didService := testDIDService(t, s, keyStoreService)
	schemaService := testSchemaService(t, s, keyStoreService, didService)
	credService, err := credential.NewCredentialService(serviceConfig, s, keyStoreService, didService.GetResolver(), schemaService)
	require.NoError(t, err)
	require.NotEmpty(t, credService)

	// check type and status
	require.Equal(t, framework.Credential, credService.Type())
	require.Equal(t, framework.StatusReady, credService.Status().Status)

	// create a did
	issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{Method: didsdk.KeyMethod, KeyType: crypto.Ed25519})
	require.NoError(t, err)
	require.NotEmpty(t, issuerDID)

	// create a schema
	createdSchema, err := schemaService.CreateSchema(context.Background(), schema.CreateSchemaRequest{Issuer: issuerDID.DID.ID, Name: "simple schema", Schema: getEmailSchema()})
	require.NoError(t, err)
	require.NotEmpty(t, createdSchema)

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
