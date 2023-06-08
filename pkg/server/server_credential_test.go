package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"

	credsdk "github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
)

func TestCredentialAPI(t *testing.T) {
	t.Run("Batch Create Credentials", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		batchCreateCredentialsRequest := router.BatchCreateCredentialsRequest{
			Requests: []router.CreateCredentialRequest{
				{
					Issuer:    issuerDID.DID.ID,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				},
				{
					Issuer:    issuerDID.DID.ID,
					IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:   "did:abc:789",
					Data: map[string]any{
						"firstName": "Lemony",
						"lastName":  "Snickets",
					},
					Expiry:    time.Now().Add(12 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				},
			},
		}
		tt.Run("Returns Many Credentials", func(ttt *testing.T) {
			requestValue := newRequestValue(ttt, batchCreateCredentialsRequest)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batchCreate", requestValue)
			w := httptest.NewRecorder()
			c := newRequestContext(w, req)
			credRouter.BatchCreateCredentials(c)
			assert.True(ttt, util.Is2xxResponse(w.Code))

			var resp router.BatchCreateCredentialsResponse
			err = json.NewDecoder(w.Body).Decode(&resp)
			assert.NoError(ttt, err)

			assert.Len(ttt, resp.Credentials, 2)

			assert.NotEmpty(ttt, resp.Credentials[0].CredentialJWT)
			assert.Equal(ttt, resp.Credentials[0].Credential.Issuer, issuerDID.DID.ID)
			assert.Equal(ttt, "did:abc:456", resp.Credentials[0].Credential.CredentialSubject.GetID())
			assert.Equal(ttt, "Jack", resp.Credentials[0].Credential.CredentialSubject["firstName"])
			assert.Equal(ttt, "Dorsey", resp.Credentials[0].Credential.CredentialSubject["lastName"])
			assert.Empty(ttt, resp.Credentials[0].Credential.CredentialStatus)

			assert.NotEmpty(ttt, resp.Credentials[1].CredentialJWT)
			assert.Equal(ttt, resp.Credentials[1].Credential.Issuer, issuerDID.DID.ID)
			assert.Equal(ttt, "did:abc:789", resp.Credentials[1].Credential.CredentialSubject.GetID())
			assert.Equal(ttt, "Lemony", resp.Credentials[1].Credential.CredentialSubject["firstName"])
			assert.Equal(ttt, "Snickets", resp.Credentials[1].Credential.CredentialSubject["lastName"])
			assert.NotEmpty(ttt, resp.Credentials[1].Credential.CredentialStatus)
		})

		tt.Run("Fails with malformed request", func(ttt *testing.T) {
			batchCreateCredentialsRequest := batchCreateCredentialsRequest
			// missing the data field
			batchCreateCredentialsRequest.Requests = append(batchCreateCredentialsRequest.Requests, router.CreateCredentialRequest{
				Issuer:    issuerDID.DID.ID,
				IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
				Subject:   "did:abc:456",
				Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			})

			requestValue := newRequestValue(ttt, batchCreateCredentialsRequest)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batchCreate", requestValue)
			w := httptest.NewRecorder()
			c := newRequestContext(w, req)
			credRouter.BatchCreateCredentials(c)
			assert.Equal(ttt, http.StatusBadRequest, w.Code)
			assert.Contains(ttt, w.Body.String(), "invalid batch create credential request")
		})

		tt.Run("Fails with more than 1000 requests", func(ttt *testing.T) {
			batchCreateCredentialsRequest := batchCreateCredentialsRequest
			// missing the data field
			for i := 0; i < 1000; i++ {
				batchCreateCredentialsRequest.Requests = append(batchCreateCredentialsRequest.Requests, batchCreateCredentialsRequest.Requests[0])
			}

			requestValue := newRequestValue(ttt, batchCreateCredentialsRequest)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batchCreate", requestValue)
			w := httptest.NewRecorder()
			c := newRequestContext(w, req)
			credRouter.BatchCreateCredentials(c)
			assert.Equal(ttt, http.StatusBadRequest, w.Code)
			assert.Contains(ttt, w.Body.String(), "max number of requests is 1000")
		})
	})
	t.Run("Test Create Credential", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// missing required field: data
		badCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		badRequestValue := newRequestValue(tt, badCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.Contains(tt, w.Body.String(), "invalid create credential request")

		// reset the http recorder
		w = httptest.NewRecorder()

		// missing known issuer request
		missingIssuerRequest := router.CreateCredentialRequest{
			Issuer:    "did:abc:123",
			IssuerKID: "did:abc:123#key-1",
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		missingIssuerRequestValue := newRequestValue(tt, missingIssuerRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", missingIssuerRequestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.Contains(tt, w.Body.String(), "getting key for signing credential<did:abc:123#key-1>")

		// reset the http recorder
		w = httptest.NewRecorder()

		// good request
		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)
		after, found := strings.CutPrefix(resp.Credential.ID, "https://ssi-service.com/v1/credentials/")
		assert.True(tt, found)
		assert.NotPanics(tt, func() {
			uuid.MustParse(after)
		})
	})

	t.Run("Test Create Credential with Schema", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

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

		w := httptest.NewRecorder()

		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			SchemaID:  createdSchema.ID,
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by schema
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", createdSchema.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"schema": createdSchema.ID})
		credRouter.ListCredentials(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getCredsResp router.ListCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)

		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].Credential.CredentialSchema.ID)

		// reset the http recorder
		w = httptest.NewRecorder()

		// create cred with unknown schema
		missingSchemaCred := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			SchemaID:  "bad",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue = newRequestValue(tt, missingSchemaCred)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.Contains(tt, w.Body.String(), "schema not found")
	})

	t.Run("Test Get Credential By ID", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		// get a cred that doesn't exit
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		c := newRequestContext(w, req)
		credRouter.GetCredential(c)
		assert.Contains(tt, w.Body.String(), "cannot get credential without ID parameter")

		// reset the http recorder
		w = httptest.NewRecorder()

		// get a cred with an invalid id parameter
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
		credRouter.GetCredential(c)
		assert.Contains(tt, w.Body.String(), "could not get credential with id: bad")

		// reset the http recorder
		w = httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		// We expect a JWT credential
		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.Credential)
		assert.NotEmpty(tt, resp.CredentialJWT)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by id
		req = httptest.NewRequest(http.MethodGet, resp.Credential.ID, nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(resp.Credential.ID)})
		credRouter.GetCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.NotEmpty(tt, getCredResp.CredentialJWT)
		assert.Equal(tt, resp.Credential.ID, getCredResp.Credential.ID)
	})

	t.Run("Test Get Credential By Schema", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

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

		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			SchemaID:  createdSchema.ID,
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by schema
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", createdSchema.ID), nil)
		c = newRequestContext(w, req)
		credRouter.ListCredentials(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getCredsResp router.ListCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)
		assert.Len(tt, getCredsResp.Credentials, 1)

		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
		assert.Equal(tt, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].Credential.CredentialSchema.ID)
	})

	t.Run("Get Credential No Param", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by issuer id
		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials", nil)
		c = newRequestContext(w, req)
		credRouter.ListCredentials(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getCredsResp router.ListCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)

		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
	})

	t.Run("Test Get Credential By Issuer", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, resp.CredentialJWT)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by issuer id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?issuer=%s", issuerDID.DID.ID), nil)
		c = newRequestContext(w, req)
		credRouter.ListCredentials(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getCredsResp router.ListCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&getCredsResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredsResp)

		assert.Len(tt, getCredsResp.Credentials, 1)
		assert.Equal(tt, resp.Credential.ID, getCredsResp.Credentials[0].ID)
	})

	t.Run("Test Get Credential By Subject", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		w := httptest.NewRecorder()

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		subjectID := "did:abc:456"
		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   subjectID,
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var createCredentialResponse router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&createCredentialResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, createCredentialResponse.CredentialJWT)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by subject id
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?subject=%s", subjectID), nil)
		c = newRequestContext(w, req)
		credRouter.ListCredentials(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var listCredentialsResponse router.ListCredentialsResponse
		err = json.NewDecoder(w.Body).Decode(&listCredentialsResponse)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, listCredentialsResponse)

		assert.Len(tt, listCredentialsResponse.Credentials, 1)
		assert.Equal(tt, createCredentialResponse.Credential.ID, listCredentialsResponse.Credentials[0].ID)
		assert.Equal(tt, createCredentialResponse.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty], listCredentialsResponse.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
	})

	t.Run("Test Delete Credential", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		w := httptest.NewRecorder()
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		// reset the http recorder
		w = httptest.NewRecorder()

		// get credential by id
		credID := resp.Credential.ID
		req = httptest.NewRequest(http.MethodGet, credID, nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(credID)})
		credRouter.GetCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var getCredResp router.GetCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&getCredResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, getCredResp)
		assert.Equal(tt, credID, getCredResp.Credential.ID)

		// reset the http recorder
		w = httptest.NewRecorder()

		// delete it
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": credID})
		credRouter.DeleteCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		// reset the http recorder
		w = httptest.NewRecorder()

		// get it back
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": credID})
		credRouter.GetCredential(c)
		assert.Contains(tt, w.Body.String(), fmt.Sprintf("could not get credential with id: %s", credID))
	})

	t.Run("Test Verifying a Credential", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		// good request
		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		w := httptest.NewRecorder()
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		// reset the http recorder
		w = httptest.NewRecorder()

		// verify the credential
		requestValue = newRequestValue(tt, router.VerifyCredentialRequest{CredentialJWT: resp.CredentialJWT})
		req = httptest.NewRequest(http.MethodPost, "https://ssi-service.com/v1/credentials/verification", requestValue)
		c = newRequestContext(w, req)
		credRouter.VerifyCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var verifyResp router.VerifyCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&verifyResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifyResp)
		assert.True(tt, verifyResp.Verified)

		// bad credential
		requestValue = newRequestValue(tt, router.VerifyCredentialRequest{CredentialJWT: keyaccess.JWTPtr("bad")})
		req = httptest.NewRequest(http.MethodPost, "https://ssi-service.com/v1/credentials/verification", requestValue)
		c = newRequestContext(w, req)
		credRouter.VerifyCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		err = json.NewDecoder(w.Body).Decode(&verifyResp)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifyResp)
		assert.False(tt, verifyResp.Verified)
		assert.Contains(tt, verifyResp.Reason, "could not parse credential from JWT")
	})

	t.Run("Test Create Revocable Credential", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		issuerDIDTwo, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDIDTwo)

		w := httptest.NewRecorder()

		// good request One
		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NoError(tt, err)
		assert.Empty(tt, resp.Credential.CredentialStatus)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		// good revocable request One
		createRevocableCredRequestOne := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestOne)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var revocableRespOne router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespOne)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespOne.CredentialJWT)
		assert.NotEmpty(tt, revocableRespOne.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespOne.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok := revocableRespOne.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		// good revocable request Two
		createRevocableCredRequestTwo := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestTwo)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var revocableRespTwo router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespTwo)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespTwo.CredentialJWT)
		assert.NotEmpty(tt, revocableRespTwo.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespTwo.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok = revocableRespTwo.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		// good revocable request Three
		createRevocableCredRequestThree := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestThree)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var revocableRespThree router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespThree)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespThree.CredentialJWT)
		assert.NotEmpty(tt, revocableRespThree.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespThree.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok = revocableRespThree.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		// good revocable request Four (different issuer / schema)
		createRevocableCredRequestFour := router.CreateCredentialRequest{
			Issuer:    issuerDIDTwo.DID.ID,
			IssuerKID: issuerDIDTwo.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue = newRequestValue(tt, createRevocableCredRequestFour)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c = newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var revocableRespFour router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&revocableRespFour)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, revocableRespFour.CredentialJWT)
		assert.NotEmpty(tt, revocableRespFour.Credential.CredentialStatus)
		assert.Equal(tt, revocableRespFour.Credential.Issuer, issuerDIDTwo.DID.ID)

		credStatusMap, ok = revocableRespFour.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])
	})

	t.Run("Test Get Revoked Status Of Credential", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		w := httptest.NewRecorder()

		// good request number one
		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NotEmpty(tt, resp.Credential.CredentialStatus)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok := resp.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s/status", resp.Credential.ID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(resp.Credential.ID)})
		credRouter.GetCredentialStatus(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var credStatusResponse = router.GetCredentialStatusResponse{}
		err = json.NewDecoder(w.Body).Decode(&credStatusResponse)
		assert.NoError(tt, err)
		assert.Equal(tt, false, credStatusResponse.Revoked)

		// good request number one
		updateCredStatusRequest := router.UpdateCredentialStatusRequest{Revoked: true}

		requestValue = newRequestValue(tt, updateCredStatusRequest)
		req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("%s/status", resp.Credential.ID), requestValue)
		c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(resp.Credential.ID)})
		credRouter.UpdateCredentialStatus(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var credStatusUpdateResponse = router.UpdateCredentialStatusResponse{}
		err = json.NewDecoder(w.Body).Decode(&credStatusUpdateResponse)
		assert.NoError(tt, err)
		assert.Equal(tt, true, credStatusUpdateResponse.Revoked)

	})

	t.Run("Test Get Status List Credential", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotEmpty(tt, bolt)

		keyStoreService := testKeyStoreService(tt, bolt)
		didService := testDIDService(tt, bolt, keyStoreService)
		schemaService := testSchemaService(tt, bolt, keyStoreService, didService)
		credRouter := testCredentialRouter(tt, bolt, keyStoreService, didService, schemaService)

		issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
			Method:  didsdk.KeyMethod,
			KeyType: crypto.Ed25519,
		})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, issuerDID)

		w := httptest.NewRecorder()

		// good request number one
		createCredRequest := router.CreateCredentialRequest{
			Issuer:    issuerDID.DID.ID,
			IssuerKID: issuerDID.DID.VerificationMethod[0].ID,
			Subject:   "did:abc:456",
			Data: map[string]any{
				"firstName": "Jack",
				"lastName":  "Dorsey",
			},
			Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			Revocable: true,
		}

		requestValue := newRequestValue(tt, createCredRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
		c := newRequestContext(w, req)
		credRouter.CreateCredential(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var resp router.CreateCredentialResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, resp.CredentialJWT)
		assert.NotEmpty(tt, resp.Credential.CredentialStatus)
		assert.Equal(tt, resp.Credential.Issuer, issuerDID.DID.ID)

		credStatusMap, ok := resp.Credential.CredentialStatus.(map[string]any)
		assert.True(tt, ok)

		assert.NotEmpty(tt, credStatusMap["statusListIndex"])

		credStatusListID := (credStatusMap["statusListCredential"]).(string)

		assert.NotEmpty(tt, credStatusListID)

		i := strings.LastIndex(credStatusListID, "/")
		uuidStringUUID := credStatusListID[i+1:]

		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:8080/%s", credStatusListID), nil)
		c = newRequestContextWithParams(w, req, map[string]string{"id": uuidStringUUID})
		credRouter.GetCredentialStatusList(c)
		assert.True(tt, util.Is2xxResponse(w.Code))

		var credListResp router.GetCredentialStatusListResponse
		err = json.NewDecoder(w.Body).Decode(&credListResp)
		assert.NoError(tt, err)

		assert.NotEmpty(tt, credListResp.CredentialJWT)
		assert.Empty(tt, credListResp.Credential.CredentialStatus)
		assert.Equal(tt, credListResp.Credential.ID, credStatusListID)
	})
}
