package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestCredentialAPI(t *testing.T) {
	t.Run("Test Create Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// missing required field: data
		badCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Expiry:  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		badRequestValue := newRequestValue(tt, badCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", badRequestValue)
		w := httptest.NewRecorder()

		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create credential request")

		// reset the http recorder
		w.Flush()

		// missing known issuer request
		missingIssuerRequest := router.CreateCredentialRequest{
			Issuer:  "did:abc:123",
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		missingIssuerRequestValue := newRequestValue(tt, missingIssuerRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", missingIssuerRequestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get key for signing credential with key<did:abc:123>")

		// reset the http recorder
		w.Flush()

		// good request
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)
	})

	t.Run("Test Create Credential with Schema", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema
		simpleSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"firstName": map[string]interface{}{
					"type": "string",
				},
				"lastName": map[string]interface{}{
					"type": "string",
				},
			},
			"required":             []interface{}{"firstName", "lastName"},
			"additionalProperties": false,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Schema:  createdSchema.ID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		w.Flush()

		// get credential by schema
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", createdSchema.ID), nil)
		err = credRouter.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)

		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].Credential.CredentialSchema.ID)

		w.Flush()

		// create cred with unknown schema
		missingSchemaCred := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Schema:  "bad",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue = newRequestValue(tt, missingSchemaCred)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "schema not found")
	})

	t.Run("Test Get Credential By ID", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		// get a cred that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		err = credRouter.GetCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get credential without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get a cred with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		err = credRouter.GetCredential(newRequestContextWithParams(map[string]string{"id": "bad"}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get credential with id: bad")

		// reset recorder between calls
		w.Flush()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		// We expect a JWT credential
		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.Credential)
		assert.NotEmpty(tt, resp.CredentialJWT)

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", resp.Credential.ID), nil)
		err = credRouter.GetCredential(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.NoError(tt, err)

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.NotEmpty(tt, getCredResp.CredentialJWT)
		assert.Equal(tt, resp.Credential.ID, getCredResp.ID)
	})

	t.Run("Test Get Credential By Schema", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// create a schema
		simpleSchema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"firstName": map[string]interface{}{
					"type": "string",
				},
				"lastName": map[string]interface{}{
					"type": "string",
				},
			},
			"required":             []interface{}{"firstName", "lastName"},
			"additionalProperties": false,
		}
		createdSchema, err := schemaService.CreateSchema(schema.CreateSchemaRequest{Author: "me", Name: "simple schema", Schema: simpleSchema})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createdSchema)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Schema:  createdSchema.ID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		w.Flush()

		// get credential by schema
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", createdSchema.ID), nil)
		err = credRouter.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)

		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].Credential.CredentialSchema.ID)
	})

	t.Run("Test Get Credential By Issuer", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		w.Flush()

		// get credential by issuer id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?issuer=%s", issuerDID.DID.ID), nil)
		err = credRouter.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)

		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
	})

	t.Run("Test Get Credential By Subject", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		subjectID := "did:abc:456"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: subjectID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		w.Flush()

		// get credential by subject id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?subject=%s", subjectID), nil)
		err = credRouter.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)

		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty], getCredsResp.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
	})

	t.Run("Test Delete Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		w := httptest.NewRecorder()
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		w.Flush()

		// get credential by id
		credID := resp.Credential.ID
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		err = credRouter.GetCredential(newRequestContextWithParams(map[string]string{"id": credID}), w, req)
		assert.NoError(tt, err)

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.Equal(tt, credID, getCredResp.Credential.ID)

		w.Flush()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		err = credRouter.DeleteCredential(newRequestContextWithParams(map[string]string{"id": credID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		err = credRouter.GetCredential(newRequestContextWithParams(map[string]string{"id": credID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get credential with id: %s", credID))
	})

	t.Run("Test Verifying a Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// good request
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		w := httptest.NewRecorder()
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		w.Flush()

		// verify the credential
		requestValue = newRequestValue(tt, router.VerifyCredentialRequest{CredentialJWT: resp.CredentialJWT})
		req = httptest.NewRequest(http.MethodPost, "https://ssi-service.com/v1/credentials/verification", requestValue)
		err = credRouter.VerifyCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var verifyResp router.VerifyCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&verifyResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifyResp)
		assert.True(tt, verifyResp.Verified)

		// bad credential
		requestValue = newRequestValue(tt, router.VerifyCredentialRequest{CredentialJWT: keyaccess.JWTPtr("bad")})
		req = httptest.NewRequest(http.MethodPost, "https://ssi-service.com/v1/credentials/verification", requestValue)
		err = credRouter.VerifyCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		err = json.NewDecoder(w.Body).Decode(&verifyResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifyResp)
		assert.False(tt, verifyResp.Verified)
		assert.Contains(tt, verifyResp.Reason, "could not parse credential from JWT")
	})

	t.Run("Test Create Revocable Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		issuerDIDTwo, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDIDTwo)

		w := httptest.NewRecorder()

		// good request One
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.Empty(tt, resp.Credential.CredentialStatus)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		// good revocable request One
		createRevocableCredRequestOne := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestOne)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var revocableRespOne router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespOne)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespOne.CredentialJWT)
		assert.NotEmpty(tt, revocableRespOne.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespOne.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok := revocableRespOne.Credential.CredentialStatus.(map[string]interface{})
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		// good revocable request Two
		createRevocableCredRequestTwo := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestTwo)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var revocableRespTwo router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespTwo)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespTwo.CredentialJWT)
		assert.NotEmpty(tt, revocableRespTwo.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespTwo.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok = revocableRespTwo.Credential.CredentialStatus.(map[string]interface{})
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		// good revocable request Three
		createRevocableCredRequestThree := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestThree)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var revocableRespThree router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespThree)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespThree.CredentialJWT)
		assert.NotEmpty(tt, revocableRespThree.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespThree.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok = revocableRespThree.Credential.CredentialStatus.(map[string]interface{})
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		// good revocable request Four (different issuer / schema)
		createRevocableCredRequestFour := router.CreateCredentialRequest{
			Issuer:  issuerDIDTwo.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestFour)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var revocableRespFour router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespFour)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespFour.CredentialJWT)
		assert.NotEmpty(tt, revocableRespFour.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespFour.Credential.Issuer, issuerDIDTwo.DID.ID)

		credStatusMap, ok = revocableRespFour.Credential.CredentialStatus.(map[string]interface{})
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])
	})

	t.Run("Test Get Revoked Status Of Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		w := httptest.NewRecorder()

		// good request number one
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NotEmpty(tt, resp.Credential.CredentialStatus)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok := resp.Credential.CredentialStatus.(map[string]interface{})
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s/status", resp.Credential.ID), nil)
		err = credRouter.GetCredentialStatus(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.NoError(tt, err)

		var credStatusResponse = router.GetCredentialStatusResponse{}
		err = json.NewDecoder(w.Body).Decode(&credStatusResponse)
		assert.NoError(tt, err)
		assert.Equal(tt, false, credStatusResponse.Revoked)

		// good request number one
		updateCredStatusRequest := router.UpdateCredentialStatusRequest{Revoked: true}

		requestValue = newRequestValue(tt, updateCredStatusRequest)
		req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s/status", resp.Credential.ID), requestValue)
		err = credRouter.UpdateCredentialStatus(newRequestContextWithParams(map[string]string{"id": resp.Credential.ID}), w, req)
		assert.NoError(tt, err)

		var credStatusUpdateResponse = router.UpdateCredentialStatusResponse{}
		err = json.NewDecoder(w.Body).Decode(&credStatusUpdateResponse)
		assert.NoError(tt, err)
		assert.Equal(tt, true, credStatusUpdateResponse.Revoked)

	})

	t.Run("Test Get Status List Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()
		require.NoError(tt, err)

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		w := httptest.NewRecorder()

		// good request number one
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credRouter.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NotEmpty(tt, resp.Credential.CredentialStatus)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok := resp.Credential.CredentialStatus.(map[string]interface{})
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		credStatusListID := (credStatusMap["statusListCredential"]).(string)

		assert.NotEmpty(tt, credStatusListID)
		fmt.Println(credStatusListID)

		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:8080/v1/credentials/status/%s", credStatusListID), nil)
		err = credRouter.GetCredentialStatusList(newRequestContextWithParams(map[string]string{"id": credStatusListID}), w, req)
		assert.NoError(tt, err)

		var credListResp router.GetCredentialStatusListResponse
		err = json.NewDecoder(w.Body).Decode(&credListResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, credListResp.CredentialJWT)
		assert.Empty(tt, credListResp.Credential.CredentialStatus)
		assert.Equal(tt, credListResp.Credential.ID, credStatusListID)
	})
}
