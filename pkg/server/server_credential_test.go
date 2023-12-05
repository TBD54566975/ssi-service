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
	"github.com/mohae/deepcopy"

	"github.com/tbd54566975/ssi-service/pkg/testutil"

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

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Batch Update Credential Status", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				batchCreateCredentialsRequest := router.BatchCreateCredentialsRequest{
					Requests: []router.CreateCredentialRequest{
						{
							Issuer:               issuerDID.DID.ID,
							VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
							Subject:              "did:abc:456",
							Data: map[string]any{
								"firstName": "Jack",
								"lastName":  "Dorsey",
							},
							Suspendable: true,
						},
						{
							Issuer:               issuerDID.DID.ID,
							VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
							Subject:              "did:abc:789",
							Data: map[string]any{
								"firstName": "Lemony",
								"lastName":  "Snickets",
							},
							Revocable: true,
						},
						{
							Issuer:               issuerDID.DID.ID,
							VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
							Subject:              "did:abc:abc",
							Data: map[string]any{
								"firstName": "Curtis",
								"lastName":  "Fictious",
							},
							Suspendable: true,
						},
					},
				}
				requestValue := newRequestValue(t, batchCreateCredentialsRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batch", requestValue)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				credRouter.BatchCreateCredentials(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.BatchCreateCredentialsResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				assert.Len(t, resp.Credentials, 3)

				// Now we got to updates
				updateCredStatusRequest := router.BatchUpdateCredentialStatusRequest{
					Requests: []router.SingleUpdateCredentialStatusRequest{
						{
							ID: idFromURI(resp.Credentials[0].ID),
							UpdateCredentialStatusRequest: router.UpdateCredentialStatusRequest{
								Suspended: true,
							},
						},
						{
							ID: idFromURI(resp.Credentials[1].ID),
							UpdateCredentialStatusRequest: router.UpdateCredentialStatusRequest{
								Revoked: true,
							},
						},
						{
							ID: idFromURI(resp.Credentials[2].ID),
							UpdateCredentialStatusRequest: router.UpdateCredentialStatusRequest{
								Suspended: true,
							},
						},
					},
				}

				t.Run("empty batch returns success", func(t *testing.T) {
					requestValue = newRequestValue(t, router.BatchUpdateCredentialStatusRequest{
						Requests: []router.SingleUpdateCredentialStatusRequest{},
					})
					req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/status/batch", requestValue)
					w = httptest.NewRecorder()
					c = newRequestContext(w, req)
					credRouter.BatchUpdateCredentialStatus(c)
					assert.True(t, util.Is2xxResponse(w.Code))
				})

				t.Run("all credentials are updated", func(t *testing.T) {
					requestValue = newRequestValue(t, updateCredStatusRequest)
					req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/status/batch", requestValue)
					w = httptest.NewRecorder()
					c = newRequestContext(w, req)
					credRouter.BatchUpdateCredentialStatus(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var credStatusUpdateResponse router.BatchUpdateCredentialStatusResponse
					err = json.NewDecoder(w.Body).Decode(&credStatusUpdateResponse)
					assert.NoError(t, err)

					assert.Len(t, credStatusUpdateResponse.CredentialStatuses, 3)
					assert.True(t, credStatusUpdateResponse.CredentialStatuses[0].Suspended)
					assert.True(t, credStatusUpdateResponse.CredentialStatuses[1].Revoked)
					assert.True(t, credStatusUpdateResponse.CredentialStatuses[2].Suspended)
				})

				t.Run("updates are idempotent", func(t *testing.T) {
					requestValue = newRequestValue(t, updateCredStatusRequest)
					req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/status/batch", requestValue)
					w = httptest.NewRecorder()
					c = newRequestContext(w, req)
					credRouter.BatchUpdateCredentialStatus(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var credStatusUpdateResponse router.BatchUpdateCredentialStatusResponse
					err = json.NewDecoder(w.Body).Decode(&credStatusUpdateResponse)
					assert.NoError(t, err)

					assert.Len(t, credStatusUpdateResponse.CredentialStatuses, 3)
					assert.True(t, credStatusUpdateResponse.CredentialStatuses[0].Suspended)
					assert.True(t, credStatusUpdateResponse.CredentialStatuses[1].Revoked)
					assert.True(t, credStatusUpdateResponse.CredentialStatuses[2].Suspended)
				})

				t.Run("missing ID fails", func(t *testing.T) {
					updateCredStatusRequest := deepcopy.Copy(updateCredStatusRequest).(router.BatchUpdateCredentialStatusRequest)
					updateCredStatusRequest.Requests[0].ID = ""
					requestValue = newRequestValue(t, updateCredStatusRequest)
					req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/status/batch", requestValue)
					w = httptest.NewRecorder()
					c = newRequestContext(w, req)
					credRouter.BatchUpdateCredentialStatus(c)
					assert.False(t, util.Is2xxResponse(w.Code))

					var errJSON map[string]any
					err = json.NewDecoder(w.Body).Decode(&errJSON)
					assert.NoError(t, err)

					assert.Contains(t, errJSON["error"], "field validation error")
				})

				t.Run("second credential does not exist", func(t *testing.T) {
					updateCredStatusRequest := deepcopy.Copy(updateCredStatusRequest).(router.BatchUpdateCredentialStatusRequest)
					updateCredStatusRequest.Requests[1].ID = "made up id 1"
					requestValue = newRequestValue(t, updateCredStatusRequest)
					req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/status/batch", requestValue)
					w = httptest.NewRecorder()
					c = newRequestContext(w, req)
					credRouter.BatchUpdateCredentialStatus(c)
					assert.False(t, util.Is2xxResponse(w.Code))

					var errJSON map[string]any
					err = json.NewDecoder(w.Body).Decode(&errJSON)
					assert.NoError(t, err)

					assert.Contains(t, errJSON["error"], "credential not found with id: made up id 1")
				})

				t.Run("revoking a suspendable credential returns error", func(t *testing.T) {
					updateCredStatusRequest := deepcopy.Copy(updateCredStatusRequest).(router.BatchUpdateCredentialStatusRequest)
					updateCredStatusRequest.Requests[2].Revoked = true
					updateCredStatusRequest.Requests[2].Suspended = false
					requestValue = newRequestValue(t, updateCredStatusRequest)
					req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/status/batch", requestValue)
					w = httptest.NewRecorder()
					c = newRequestContext(w, req)
					credRouter.BatchUpdateCredentialStatus(c)
					assert.False(t, util.Is2xxResponse(w.Code))

					var errJSON map[string]any
					err = json.NewDecoder(w.Body).Decode(&errJSON)
					assert.NoError(t, err)

					assert.Contains(t, errJSON["error"], "has a different status purpose<suspension> value than the status credential<revocation>")
				})
			})

			t.Run("Batch Create Credentials", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				batchCreateCredentialsRequest := router.BatchCreateCredentialsRequest{
					Requests: []router.CreateCredentialRequest{
						{
							Issuer:               issuerDID.DID.ID,
							VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
							Subject:              "did:abc:456",
							Data: map[string]any{
								"firstName": "Jack",
								"lastName":  "Dorsey",
							},
							Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
						},
						{
							Issuer:               issuerDID.DID.ID,
							VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
							Subject:              "did:abc:789",
							Data: map[string]any{
								"firstName": "Lemony",
								"lastName":  "Snickets",
							},
							Expiry:    time.Now().Add(12 * time.Hour).Format(time.RFC3339),
							Revocable: true,
						},
					},
				}
				t.Run("Returns Many Credentials", func(t *testing.T) {
					requestValue := newRequestValue(t, batchCreateCredentialsRequest)
					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batch", requestValue)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					credRouter.BatchCreateCredentials(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var resp router.BatchCreateCredentialsResponse
					err = json.NewDecoder(w.Body).Decode(&resp)
					assert.NoError(t, err)

					assert.Len(t, resp.Credentials, 2)

					assert.NotEmpty(t, resp.Credentials[0].CredentialJWT)
					assert.Equal(t, resp.Credentials[0].Credential.Issuer, issuerDID.DID.ID)
					assert.Equal(t, "did:abc:456", resp.Credentials[0].Credential.CredentialSubject.GetID())
					assert.Equal(t, "Jack", resp.Credentials[0].Credential.CredentialSubject["firstName"])
					assert.Equal(t, "Dorsey", resp.Credentials[0].Credential.CredentialSubject["lastName"])
					assert.Empty(t, resp.Credentials[0].Credential.CredentialStatus)

					assert.NotEmpty(t, resp.Credentials[1].CredentialJWT)
					assert.Equal(t, resp.Credentials[1].Credential.Issuer, issuerDID.DID.ID)
					assert.Equal(t, "did:abc:789", resp.Credentials[1].Credential.CredentialSubject.GetID())
					assert.Equal(t, "Lemony", resp.Credentials[1].Credential.CredentialSubject["firstName"])
					assert.Equal(t, "Snickets", resp.Credentials[1].Credential.CredentialSubject["lastName"])
					assert.NotEmpty(t, resp.Credentials[1].Credential.CredentialStatus)
				})

				t.Run("Fails with malformed request", func(t *testing.T) {
					batchCreateCredentialsRequest := batchCreateCredentialsRequest
					// missing the data field
					batchCreateCredentialsRequest.Requests = append(batchCreateCredentialsRequest.Requests, router.CreateCredentialRequest{
						Issuer:               issuerDID.DID.ID,
						VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
						Subject:              "did:abc:456",
						Expiry:               time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					})

					requestValue := newRequestValue(t, batchCreateCredentialsRequest)
					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batch", requestValue)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					credRouter.BatchCreateCredentials(c)
					assert.Equal(t, http.StatusBadRequest, w.Code)
					assert.Contains(t, w.Body.String(), "invalid batch create credential request")
				})

				t.Run("Fails with more than 1000 requests", func(t *testing.T) {
					batchCreateCredentialsRequest := batchCreateCredentialsRequest
					// missing the data field
					for i := 0; i < 1000; i++ {
						batchCreateCredentialsRequest.Requests = append(batchCreateCredentialsRequest.Requests, batchCreateCredentialsRequest.Requests[0])
					}

					requestValue := newRequestValue(t, batchCreateCredentialsRequest)
					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials/batch", requestValue)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					credRouter.BatchCreateCredentials(c)
					assert.Equal(t, http.StatusBadRequest, w.Code)
					assert.Contains(t, w.Body.String(), "max number of requests is 1000")
				})
			})

			t.Run("Test Create Credential", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// missing required field: data
				badCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Expiry:               time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				badRequestValue := newRequestValue(t, badCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.Contains(t, w.Body.String(), "invalid create credential request")

				// reset the http recorder
				w = httptest.NewRecorder()

				// missing known issuer request
				missingIssuerRequest := router.CreateCredentialRequest{
					Issuer:               "did:abc:123",
					VerificationMethodID: "did:abc:123#key-1",
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				missingIssuerRequestValue := newRequestValue(t, missingIssuerRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", missingIssuerRequestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.Contains(t, w.Body.String(), "getting key for signing credential<did:abc:123#key-1>")

				// reset the http recorder
				w = httptest.NewRecorder()

				// good request
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				assert.NotEmpty(t, resp.CredentialJWT)
				assert.NoError(t, err)
				assert.Equal(t, resp.Credential.Issuer, issuerDID.DID.ID)
				after, found := strings.CutPrefix(resp.Credential.ID, "https://ssi-service.com/v1/credentials/")
				assert.True(t, found)
				assert.NotPanics(t, func() {
					uuid.MustParse(after)
				})
			})

			t.Run("Test Create Credential with Schema", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

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
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				w := httptest.NewRecorder()

				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					SchemaID:             createdSchema.ID,
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.CredentialJWT)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by schema
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", createdSchema.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"schema": createdSchema.ID})
				credRouter.ListCredentials(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getCredsResp router.ListCredentialsResponse
				err = json.NewDecoder(w.Body).Decode(&getCredsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getCredsResp)
				assert.Len(t, getCredsResp.Credentials, 1)

				assert.Equal(t, resp.ID, getCredsResp.Credentials[0].ID)
				assert.Equal(t, resp.Credential.ID, getCredsResp.Credentials[0].Credential.ID)
				assert.Equal(t, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].Credential.CredentialSchema.ID)

				// reset the http recorder
				w = httptest.NewRecorder()

				// create cred with unknown schema
				missingSchemaCred := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					SchemaID:             "bad",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue = newRequestValue(t, missingSchemaCred)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.Contains(t, w.Body.String(), "schema not found")
			})

			t.Run("Test Get Credential By ID", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				w := httptest.NewRecorder()

				// get a cred that doesn't exit
				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
				c := newRequestContext(w, req)
				credRouter.GetCredential(c)
				assert.Contains(t, w.Body.String(), "cannot get credential without ID parameter")

				// reset the http recorder
				w = httptest.NewRecorder()

				// get a cred with an invalid id parameter
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials/bad", nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": "bad"})
				credRouter.GetCredential(c)
				assert.Contains(t, w.Body.String(), "could not get credential with id: bad")

				// reset the http recorder
				w = httptest.NewRecorder()

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				// We expect a JWT credential
				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.Credential)
				assert.NotEmpty(t, resp.CredentialJWT)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by id
				req = httptest.NewRequest(http.MethodGet, resp.Credential.ID, nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(resp.Credential.ID)})
				credRouter.GetCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getCredResp router.GetCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&getCredResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getCredResp)
				assert.NotEmpty(t, getCredResp.CredentialJWT)
				assert.Equal(t, resp.Credential.ID, getCredResp.Credential.ID)
			})

			t.Run("Test Get Credential By Schema", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				w := httptest.NewRecorder()

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

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
				assert.NoError(t, err)
				assert.NotEmpty(t, createdSchema)

				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					SchemaID:             createdSchema.ID,
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.CredentialJWT)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by schema
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?schema=%s", createdSchema.ID), nil)
				c = newRequestContext(w, req)
				credRouter.ListCredentials(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getCredsResp router.ListCredentialsResponse
				err = json.NewDecoder(w.Body).Decode(&getCredsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getCredsResp)
				assert.Len(t, getCredsResp.Credentials, 1)

				assert.Equal(t, resp.ID, getCredsResp.Credentials[0].ID)
				assert.Equal(t, resp.Credential.ID, getCredsResp.Credentials[0].Credential.ID)
				assert.Equal(t, resp.Credential.CredentialSchema.ID, getCredsResp.Credentials[0].Credential.CredentialSchema.ID)
			})

			t.Run("Get Credential No Param", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				w := httptest.NewRecorder()

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.CredentialJWT)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by issuer id
				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/credentials", nil)
				c = newRequestContext(w, req)
				credRouter.ListCredentials(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getCredsResp router.ListCredentialsResponse
				err = json.NewDecoder(w.Body).Decode(&getCredsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getCredsResp)

				assert.Len(t, getCredsResp.Credentials, 1)
				assert.Equal(t, resp.ID, getCredsResp.Credentials[0].ID)
				assert.Equal(t, resp.Credential.ID, getCredsResp.Credentials[0].Credential.ID)
			})

			t.Run("Test Get Credential By Issuer", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				w := httptest.NewRecorder()

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.NotEmpty(t, resp.CredentialJWT)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by issuer id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?issuer=%s", issuerDID.DID.ID), nil)
				c = newRequestContext(w, req)
				credRouter.ListCredentials(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getCredsResp router.ListCredentialsResponse
				err = json.NewDecoder(w.Body).Decode(&getCredsResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getCredsResp)

				assert.Len(t, getCredsResp.Credentials, 1)
				assert.Equal(t, resp.ID, getCredsResp.Credentials[0].ID)
				assert.Equal(t, resp.Credential.ID, getCredsResp.Credentials[0].Credential.ID)
			})

			t.Run("Test Get Credential By Subject", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				w := httptest.NewRecorder()

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				subjectID := "did:abc:456"
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              subjectID,
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var createCredentialResponse router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&createCredentialResponse)
				assert.NoError(t, err)
				assert.NotEmpty(t, createCredentialResponse.CredentialJWT)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by subject id
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credential?subject=%s", subjectID), nil)
				c = newRequestContext(w, req)
				credRouter.ListCredentials(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var listCredentialsResponse router.ListCredentialsResponse
				err = json.NewDecoder(w.Body).Decode(&listCredentialsResponse)
				assert.NoError(t, err)
				assert.NotEmpty(t, listCredentialsResponse)

				assert.Len(t, listCredentialsResponse.Credentials, 1)
				assert.Equal(t, createCredentialResponse.ID, listCredentialsResponse.Credentials[0].ID)
				assert.Equal(t, createCredentialResponse.Credential.ID, listCredentialsResponse.Credentials[0].Credential.ID)
				assert.Equal(t, createCredentialResponse.Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty], listCredentialsResponse.Credentials[0].Credential.CredentialSubject[credsdk.VerifiableCredentialIDProperty])
			})

			t.Run("Test Delete Credential", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				// reset the http recorder
				w = httptest.NewRecorder()

				// get credential by id
				credID := resp.Credential.ID
				req = httptest.NewRequest(http.MethodGet, credID, nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(credID)})
				credRouter.GetCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var getCredResp router.GetCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&getCredResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, getCredResp)
				assert.Equal(t, credID, getCredResp.Credential.ID)

				// reset the http recorder
				w = httptest.NewRecorder()

				// delete it
				req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": credID})
				credRouter.DeleteCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				// reset the http recorder
				w = httptest.NewRecorder()

				// get it back
				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/credentials/%s", credID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": credID})
				credRouter.GetCredential(c)
				assert.Contains(t, w.Body.String(), fmt.Sprintf("could not get credential with id: %s", credID))
			})

			t.Run("Test Verifying a Credential", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				// good request
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				assert.NotEmpty(t, resp.CredentialJWT)
				assert.NoError(t, err)
				assert.Equal(t, resp.Credential.Issuer, issuerDID.DID.ID)

				// reset the http recorder
				w = httptest.NewRecorder()

				// verify the credential
				requestValue = newRequestValue(t, router.VerifyCredentialRequest{CredentialJWT: resp.CredentialJWT})
				req = httptest.NewRequest(http.MethodPost, "https://ssi-service.com/v1/credentials/verification", requestValue)
				c = newRequestContext(w, req)
				credRouter.VerifyCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var verifyResp router.VerifyCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&verifyResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, verifyResp)
				assert.True(t, verifyResp.Verified)

				// bad credential
				requestValue = newRequestValue(t, router.VerifyCredentialRequest{CredentialJWT: keyaccess.JWTPtr("bad")})
				req = httptest.NewRequest(http.MethodPost, "https://ssi-service.com/v1/credentials/verification", requestValue)
				c = newRequestContext(w, req)
				credRouter.VerifyCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				err = json.NewDecoder(w.Body).Decode(&verifyResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, verifyResp)
				assert.False(t, verifyResp.Verified)
				assert.Contains(t, verifyResp.Reason, "parsing JWT: parsing credential token: invalid JWT")
			})

			t.Run("Test Create Revocable Credential", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				issuerDIDTwo, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDIDTwo)

				w := httptest.NewRecorder()

				// good request One
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				assert.NotEmpty(t, resp.CredentialJWT)
				assert.NoError(t, err)
				assert.Empty(t, resp.Credential.CredentialStatus)
				assert.Equal(t, resp.Credential.Issuer, issuerDID.DID.ID)

				// good revocable request One
				createRevocableCredRequestOne := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				}

				requestValue = newRequestValue(t, createRevocableCredRequestOne)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var revocableRespOne router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&revocableRespOne)
				assert.NoError(t, err)

				assert.NotEmpty(t, revocableRespOne.CredentialJWT)
				assert.NotEmpty(t, revocableRespOne.Credential.CredentialStatus)
				assert.Equal(t, revocableRespOne.Credential.Issuer, issuerDID.DID.ID)

				credStatusMap, ok := revocableRespOne.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				// good revocable request Two
				createRevocableCredRequestTwo := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				}

				requestValue = newRequestValue(t, createRevocableCredRequestTwo)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var revocableRespTwo router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&revocableRespTwo)
				assert.NoError(t, err)

				assert.NotEmpty(t, revocableRespTwo.CredentialJWT)
				assert.NotEmpty(t, revocableRespTwo.Credential.CredentialStatus)
				assert.Equal(t, revocableRespTwo.Credential.Issuer, issuerDID.DID.ID)

				credStatusMap, ok = revocableRespTwo.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				// good revocable request Three
				createRevocableCredRequestThree := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				}

				requestValue = newRequestValue(t, createRevocableCredRequestThree)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var revocableRespThree router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&revocableRespThree)
				assert.NoError(t, err)

				assert.NotEmpty(t, revocableRespThree.CredentialJWT)
				assert.NotEmpty(t, revocableRespThree.Credential.CredentialStatus)
				assert.Equal(t, revocableRespThree.Credential.Issuer, issuerDID.DID.ID)

				credStatusMap, ok = revocableRespThree.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				// good revocable request Four (different issuer / schema)
				createRevocableCredRequestFour := router.CreateCredentialRequest{
					Issuer:               issuerDIDTwo.DID.ID,
					VerificationMethodID: issuerDIDTwo.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				}

				requestValue = newRequestValue(t, createRevocableCredRequestFour)
				req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c = newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var revocableRespFour router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&revocableRespFour)
				assert.NoError(t, err)

				assert.NotEmpty(t, revocableRespFour.CredentialJWT)
				assert.NotEmpty(t, revocableRespFour.Credential.CredentialStatus)
				assert.Equal(t, revocableRespFour.Credential.Issuer, issuerDIDTwo.DID.ID)

				credStatusMap, ok = revocableRespFour.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.NotEmpty(t, credStatusMap["statusListIndex"])
			})

			t.Run("Test Get Revoked Status Of Credential", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				w := httptest.NewRecorder()

				// good request number one
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				}

				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				assert.NotEmpty(t, resp.CredentialJWT)
				assert.NotEmpty(t, resp.Credential.CredentialStatus)
				assert.Equal(t, resp.Credential.Issuer, issuerDID.DID.ID)

				credStatusMap, ok := resp.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s/status", resp.Credential.ID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(resp.Credential.ID)})
				credRouter.GetCredentialStatus(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var credStatusResponse = router.GetCredentialStatusResponse{}
				err = json.NewDecoder(w.Body).Decode(&credStatusResponse)
				assert.NoError(t, err)
				assert.Equal(t, false, credStatusResponse.Revoked)

				// good request number one
				updateCredStatusRequest := router.UpdateCredentialStatusRequest{Revoked: true}

				requestValue = newRequestValue(t, updateCredStatusRequest)
				req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("%s/status", resp.Credential.ID), requestValue)
				c = newRequestContextWithParams(w, req, map[string]string{"id": idFromURI(resp.Credential.ID)})
				credRouter.UpdateCredentialStatus(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var credStatusUpdateResponse = router.UpdateCredentialStatusResponse{}
				err = json.NewDecoder(w.Body).Decode(&credStatusUpdateResponse)
				assert.NoError(t, err)
				assert.Equal(t, true, credStatusUpdateResponse.Revoked)

			})

			t.Run("Test Get Status List Credential", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				keyStoreService, _ := testKeyStoreService(t, db)
				didService, _ := testDIDService(t, db, keyStoreService, nil)
				schemaService := testSchemaService(t, db, keyStoreService, didService)
				credRouter := testCredentialRouter(t, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(t, err)
				assert.NotEmpty(t, issuerDID)

				w := httptest.NewRecorder()

				// good request number one
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:abc:456",
					Data: map[string]any{
						"firstName": "Jack",
						"lastName":  "Dorsey",
					},
					Expiry:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
					Revocable: true,
				}

				requestValue := newRequestValue(t, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)

				assert.NotEmpty(t, resp.CredentialJWT)
				assert.NotEmpty(t, resp.Credential.CredentialStatus)
				assert.Equal(t, resp.Credential.Issuer, issuerDID.DID.ID)

				credStatusMap, ok := resp.Credential.CredentialStatus.(map[string]any)
				assert.True(t, ok)

				assert.NotEmpty(t, credStatusMap["statusListIndex"])

				credStatusListID := (credStatusMap["statusListCredential"]).(string)

				assert.NotEmpty(t, credStatusListID)

				i := strings.LastIndex(credStatusListID, "/")
				uuidStringUUID := credStatusListID[i+1:]

				req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:8080/%s", credStatusListID), nil)
				c = newRequestContextWithParams(w, req, map[string]string{"id": uuidStringUUID})
				credRouter.GetCredentialStatusList(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var credListResp router.GetCredentialStatusListResponse
				err = json.NewDecoder(w.Body).Decode(&credListResp)
				assert.NoError(t, err)

				assert.NotEmpty(t, credListResp.CredentialJWT)
				assert.Empty(t, credListResp.Credential.CredentialStatus)
				assert.Equal(t, credListResp.Credential.ID, credStatusListID)
			})
		})
	}
}
