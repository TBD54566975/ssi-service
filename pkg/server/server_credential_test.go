package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestCredentialAPI(t *testing.T) {
	t.Run("Test Create Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		credService := testCredentialRouter(tt, bolt, keyStoreService)
		didService := testDIDService(tt, bolt, keyStoreService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
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

		err = credService.CreateCredential(newRequestContext(), w, req)
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
		err = credService.CreateCredential(newRequestContext(), w, req)
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
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		parsedCred, err := signing.ParseVerifiableCredentialFromJWT(*resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.Equal(tt, parsedCred.Issuer, issuerDID.DID.ID)
	})

	t.Run("Test Get Credential By ID", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		credService := testCredentialRouter(tt, bolt, keyStoreService)
		didService := testDIDService(tt, bolt, keyStoreService)

		w := httptest.NewRecorder()

		// get a cred that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		err = credService.GetCredential(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "cannot get credential without ID parameter")

		// reset recorder between calls
		w.Flush()

		// get a cred with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": "bad"}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get credential with id: bad")

		// reset recorder between calls
		w.Flush()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
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
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		// We expect a JWT credential
		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Empty(tt, resp.Credential)
		assert.NotEmpty(tt, resp.CredentialJWT)

		parsedCred, err := signing.ParseVerifiableCredentialFromJWT(*resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", parsedCred.ID), nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": parsedCred.ID}), w, req)
		assert.NoError(tt, err)

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.NotEmpty(tt, getCredResp.CredentialJWT)

		parsedCredResponse, err := signing.ParseVerifiableCredentialFromJWT(*getCredResp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredResponse)
		assert.Equal(tt, parsedCredResponse.ID, getCredResp.ID)
	})

	t.Run("Test Get Credential By Schema", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		credService := testCredentialRouter(tt, bolt, keyStoreService)
		didService := testDIDService(tt, bolt, keyStoreService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		schemaID := "https://test-schema.com/name"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Schema:  schemaID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		parsedCredResponse, err := signing.ParseVerifiableCredentialFromJWT(*resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredResponse)

		w.Flush()

		// get credential by schema
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", schemaID), nil)
		err = credService.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.CredentialJWTs, 1)

		parsedCredsResponse, err := signing.ParseVerifiableCredentialFromJWT(getCredsResp.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredsResponse)

		assert.Equal(tt, parsedCredResponse.ID, parsedCredsResponse.ID)
		assert.Equal(tt, parsedCredResponse.CredentialSchema.ID, parsedCredsResponse.CredentialSchema.ID)
	})

	t.Run("Test Get Credential By Issuer", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		credService := testCredentialRouter(tt, bolt, keyStoreService)
		didService := testDIDService(tt, bolt, keyStoreService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		schemaID := "https://test-schema.com/name"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: "did:abc:456",
			Schema:  schemaID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		parsedCredResponse, err := signing.ParseVerifiableCredentialFromJWT(*resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredResponse)

		w.Flush()

		// get credential by issuer id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?issuer=%s", issuerDID.DID.ID), nil)
		err = credService.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)

		parsedCredsResponse, err := signing.ParseVerifiableCredentialFromJWT(getCredsResp.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredsResponse)

		assert.Equal(tt, parsedCredResponse.ID, parsedCredsResponse.ID)
		assert.Equal(tt, parsedCredResponse.CredentialSchema.ID, parsedCredsResponse.CredentialSchema.ID)

		assert.Len(tt, getCredsResp.CredentialJWTs, 1)
		assert.Equal(tt, parsedCredResponse.ID, parsedCredsResponse.ID)
		assert.Equal(tt, parsedCredResponse.Issuer, parsedCredsResponse.Issuer)
	})

	t.Run("Test Get Credential By Subject", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		credService := testCredentialRouter(tt, bolt, keyStoreService)
		didService := testDIDService(tt, bolt, keyStoreService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		schemaID := "https://test-schema.com/name"
		subjectID := "did:abc:456"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:  issuerDID.DID.ID,
			Subject: subjectID,
			Schema:  schemaID,
			Data: map[string]interface{}{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		parsedCredResponse, err := signing.ParseVerifiableCredentialFromJWT(*resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredResponse)

		w.Flush()

		// get credential by subject id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?subject=%s", subjectID), nil)
		err = credService.GetCredentials(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var getCredsResp router.GetCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)

		parsedCredsResponse, err := signing.ParseVerifiableCredentialFromJWT(getCredsResp.CredentialJWTs[0])
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredsResponse)

		assert.Len(tt, getCredsResp.CredentialJWTs, 1)
		assert.Equal(tt, parsedCredResponse.ID, parsedCredsResponse.ID)
		assert.Equal(tt, parsedCredResponse.CredentialSubject[credsdk.VerifiableCredentialIDProperty], parsedCredsResponse.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
	})

	t.Run("Test Delete Credential", func(tt *testing.T) {
		bolt, err := storage.NewBoltDB()

		// remove the db file after the test
		tt.Cleanup(func() {
			_ = bolt.Close()
			_ = os.Remove(storage.DBFile)
		})

		keyStoreService := testKeyStoreService(tt, bolt)
		credService := testCredentialRouter(tt, bolt, keyStoreService)
		didService := testDIDService(tt, bolt, keyStoreService)

		issuerDID, err := didService.CreateDIDByMethod(did.CreateDIDRequest{
			Method:  did.KeyMethod,
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
		err = credService.CreateCredential(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		parsedCredResponse, err := signing.ParseVerifiableCredentialFromJWT(*resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCredResponse)
		credID := parsedCredResponse.ID

		w.Flush()

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": credID}), w, req)
		assert.NoError(tt, err)

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)

		parsedGetCred, err := signing.ParseVerifiableCredentialFromJWT(*getCredResp.CredentialJWT)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedGetCred)

		assert.Equal(tt, parsedCredResponse.ID, parsedGetCred.ID)

		w.Flush()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		err = credService.DeleteCredential(newRequestContextWithParams(map[string]string{"id": credID}), w, req)
		assert.NoError(tt, err)

		w.Flush()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		err = credService.GetCredential(newRequestContextWithParams(map[string]string{"id": credID}), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), fmt.Sprintf("could not get credential with id: %s", credID))
	})
}
