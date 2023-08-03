package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/key"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/testutil"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation/model"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestPresentationAPI(t *testing.T) {
	builder := exchange.NewPresentationDefinitionBuilder()
	inputDescriptors := []exchange.InputDescriptor{
		{
			ID:      "id",
			Name:    "name",
			Purpose: "purpose",
			Format: &exchange.ClaimFormat{
				JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &exchange.Constraints{SubjectIsIssuer: exchange.Preferred.Ptr()},
		},
	}
	assert.NoError(t, builder.SetInputDescriptors(inputDescriptors))
	assert.NoError(t, builder.SetName("name"))
	assert.NoError(t, builder.SetPurpose("purpose"))
	pd, err := builder.Build()
	assert.NoError(t, err)

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(tt *testing.T) {

			tt.Run("Verify a Verifiable Presentation", func(ttt *testing.T) {
				db := test.ServiceStorage(ttt)
				presRouter, _ := setupPresentationRouter(ttt, db)

				// first, create a credential using the service
				keyStoreService, _ := testKeyStoreService(ttt, db)
				didService, _ := testDIDService(ttt, db, keyStoreService, nil)
				schemaService := testSchemaService(ttt, db, keyStoreService, didService)
				credRouter := testCredentialRouter(ttt, db, keyStoreService, didService, schemaService)

				issuerDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
					Method:  didsdk.KeyMethod,
					KeyType: crypto.Ed25519,
				})
				assert.NoError(ttt, err)
				assert.NotEmpty(ttt, issuerDID)

				// good request
				createCredRequest := router.CreateCredentialRequest{
					Issuer:               issuerDID.DID.ID,
					VerificationMethodID: issuerDID.DID.VerificationMethod[0].ID,
					Subject:              "did:car:911",
					Data: map[string]any{
						"firstName": "Frank",
						"lastName":  "Ocean",
					},
					Expiry: time.Now().Add(24 * time.Hour).Format(time.RFC3339),
				}
				requestValue := newRequestValue(ttt, createCredRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/credentials", requestValue)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				credRouter.CreateCredential(c)
				assert.True(ttt, util.Is2xxResponse(w.Code))

				var createResp router.CreateCredentialResponse
				err = json.NewDecoder(w.Body).Decode(&createResp)
				assert.NoError(ttt, err)

				assert.NotEmpty(ttt, createResp.CredentialJWT)
				assert.NoError(ttt, err)
				assert.Equal(ttt, createResp.Credential.Issuer, issuerDID.DID.ID)

				holderSigner, holderDID := getSigner(ttt)
				testPresentation := credential.VerifiablePresentation{
					Context: []string{"https://www.w3.org/2018/credentials/v1",
						"https://w3id.org/security/suites/jws-2020/v1"},
					Type:   []string{"VerifiablePresentation"},
					Holder: holderDID.String(),
				}

				// invalid verifiable presentation with no credentials
				{
					// use the sdk to create a vp
					emptyPresentation, err := integrity.SignVerifiablePresentationJWT(holderSigner, integrity.JWTVVPParameters{Audience: []string{holderSigner.ID}}, testPresentation)
					assert.NoError(tt, err)

					badPresentation := string(emptyPresentation[:10])
					value := newRequestValue(t, router.VerifyPresentationRequest{PresentationJWT: keyaccess.JWTPtr(badPresentation)})
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/presentations/verification"), value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					presRouter.VerifyPresentation(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))

					var resp router.VerifyPresentationResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.False(ttt, resp.Verified)
					assert.Equal(ttt, resp.Reason, "parsing JWT presentation: parsing vp token: invalid JWT")
				}

				// valid verifiable presentation with no credentials
				{
					// use the sdk to create a vp
					emptyPresentation, err := integrity.SignVerifiablePresentationJWT(holderSigner, integrity.JWTVVPParameters{Audience: []string{holderSigner.ID}}, testPresentation)
					assert.NoError(tt, err)

					value := newRequestValue(t, router.VerifyPresentationRequest{PresentationJWT: keyaccess.JWTPtr(string(emptyPresentation))})
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/presentations/verification"), value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					presRouter.VerifyPresentation(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))

					var resp router.VerifyPresentationResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.True(ttt, resp.Verified)
				}

				// verifiable presentation with an invalid credential signature
				{
					// add credential to the vp
					badCredJWT := createResp.CredentialJWT.String()[:10]
					testPresentation.VerifiableCredential = []any{badCredJWT}

					// use the sdk to create a vp
					emptyPresentation, err := integrity.SignVerifiablePresentationJWT(holderSigner, integrity.JWTVVPParameters{Audience: []string{holderSigner.ID}}, testPresentation)
					assert.NoError(tt, err)

					value := newRequestValue(t, router.VerifyPresentationRequest{PresentationJWT: keyaccess.JWTPtr(string(emptyPresentation))})
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/presentations/verification"), value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					presRouter.VerifyPresentation(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))

					var resp router.VerifyPresentationResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.False(ttt, resp.Verified)
					assert.Contains(ttt, resp.Reason, "verifying credential 0: parsing JWT: parsing credential token: invalid JWT")
				}

				// verifiable presentation with a valid credential signature
				{
					// add credential to the vp
					testPresentation.VerifiableCredential = []any{createResp.CredentialJWT}

					// use the sdk to create a vp
					emptyPresentation, err := integrity.SignVerifiablePresentationJWT(holderSigner, integrity.JWTVVPParameters{Audience: []string{holderSigner.ID}}, testPresentation)
					assert.NoError(tt, err)

					value := newRequestValue(t, router.VerifyPresentationRequest{PresentationJWT: keyaccess.JWTPtr(string(emptyPresentation))})
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/presentations/verification"), value)
					w := httptest.NewRecorder()
					c := newRequestContext(w, req)
					presRouter.VerifyPresentation(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))

					var resp router.VerifyPresentationResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.True(ttt, resp.Verified)
				}
			})

			tt.Run("Create, Get, and Delete Presentation Definition", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, _ := setupPresentationRouter(ttt, s)

				var createdID string
				{
					resp := createPresentationDefinition(ttt, pRouter, WithInputDescriptors(inputDescriptors))
					if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
						ttt.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
					}

					createdID = resp.PresentationDefinition.ID
				}
				{
					// We can get the PD after it's created.
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.GetDefinition(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))

					var resp router.GetPresentationDefinitionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Equal(ttt, createdID, resp.PresentationDefinition.ID)
					if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
						ttt.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
					}
				}
				{
					// And it can also be listed
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.ListDefinitions(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))

					var resp router.ListDefinitionsResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Len(ttt, resp.Definitions, 1)
					assert.Equal(ttt, createdID, resp.Definitions[0].ID)
					if diff := cmp.Diff(pd, resp.Definitions[0], cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
						ttt.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
					}
				}
				{
					// The PD can be deleted.
					req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.DeleteDefinition(c)
					assert.True(ttt, util.Is2xxResponse(w.Code))
				}
				{
					// And we cannot get the PD after it's been deleted.
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.GetDefinition(c)
					assert.Contains(ttt, w.Body.String(), "not found")
				}
			})

			tt.Run("List presentation requests returns empty", func(tt *testing.T) {
				s := test.ServiceStorage(tt)
				pRouter, _ := setupPresentationRouter(tt, s)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/requests", nil)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				pRouter.ListRequests(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.ListPresentationRequestsResponse
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Empty(tt, resp.Requests)
			})

			tt.Run("Get presentation requests returns created request", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, didService := setupPresentationRouter(ttt, s)
				issuerDID := createDID(ttt, didService)
				def := createPresentationDefinition(ttt, pRouter)
				req1 := createPresentationRequest(ttt, pRouter, def.PresentationDefinition.ID, issuerDID.DID)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/requests/"+req1.Request.ID, nil)
				w := httptest.NewRecorder()
				params := map[string]string{
					"id": req1.Request.ID,
				}
				c := newRequestContextWithParams(w, req, params)
				pRouter.GetRequest(c)
				assert.True(ttt, util.Is2xxResponse(w.Code))

				var resp router.GetRequestResponse
				assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Equal(ttt, req1.Request, resp.Request)
				assert.Equal(ttt, "my_callback_url", resp.Request.CallbackURL)
			})

			tt.Run("List presentation requests returns many requests", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, didService := setupPresentationRouter(ttt, s)
				issuerDID := createDID(ttt, didService)
				def := createPresentationDefinition(ttt, pRouter)
				req1 := createPresentationRequest(ttt, pRouter, def.PresentationDefinition.ID, issuerDID.DID)
				req2 := createPresentationRequest(ttt, pRouter, def.PresentationDefinition.ID, issuerDID.DID)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/requests", nil)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				pRouter.ListRequests(c)
				assert.True(ttt, util.Is2xxResponse(w.Code))

				var resp router.ListPresentationRequestsResponse
				assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Len(ttt, resp.Requests, 2)
				assert.ElementsMatch(ttt, resp.Requests, []model.Request{
					*req1.Request,
					*req2.Request,
				})
				assert.Equal(ttt, "my_callback_url", resp.Requests[0].CallbackURL)
			})

			tt.Run("List definitions returns empty", func(tt *testing.T) {
				s := test.ServiceStorage(tt)
				pRouter, _ := setupPresentationRouter(tt, s)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				pRouter.ListDefinitions(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.ListDefinitionsResponse
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Empty(tt, resp.Definitions)
			})

			tt.Run("List definitions returns many definitions", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, _ := setupPresentationRouter(ttt, s)
				def1 := createPresentationDefinition(ttt, pRouter)
				def2 := createPresentationDefinition(ttt, pRouter)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				pRouter.ListDefinitions(c)
				assert.True(ttt, util.Is2xxResponse(w.Code))

				var resp router.ListDefinitionsResponse
				assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Len(ttt, resp.Definitions, 2)
				assert.ElementsMatch(ttt, resp.Definitions, []*exchange.PresentationDefinition{
					&def1.PresentationDefinition,
					&def2.PresentationDefinition,
				})
			})

			tt.Run("Create returns error without input descriptors", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, _ := setupPresentationRouter(ttt, s)
				request := router.CreatePresentationDefinitionRequest{}
				value := newRequestValue(ttt, request)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				pRouter.CreateDefinition(c)
				assert.Contains(ttt, w.Body.String(), "inputDescriptors is a required field")
			})

			tt.Run("Get without an ID returns error", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, _ := setupPresentationRouter(ttt, s)
				req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
				w := httptest.NewRecorder()

				c := newRequestContextWithParams(w, req, map[string]string{"id": pd.ID})
				pRouter.GetDefinition(c)
				assert.Contains(ttt, w.Body.String(), "not found")
			})

			tt.Run("Delete without an ID returns error", func(ttt *testing.T) {
				s := test.ServiceStorage(ttt)
				pRouter, _ := setupPresentationRouter(ttt, s)

				req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
				w := httptest.NewRecorder()
				c := newRequestContextWithParams(w, req, map[string]string{"id": pd.ID})
				pRouter.DeleteDefinition(c)
				assert.Contains(ttt, w.Body.String(), fmt.Sprintf("could not delete presentation definition with id: %s", pd.ID))
			})

			tt.Run("Submission endpoints", func(ttt *testing.T) {
				ttt.Run("Get non-existing ID returns error", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, _ := setupPresentationRouter(tttt, s)

					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions/myrandomid", nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": "myrandomid"})
					pRouter.GetSubmission(c)
					assert.Contains(tttt, w.Body.String(), "not found")
				})

				ttt.Run("Get returns submission after creation", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					op := createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s", opstorage.StatusObjectID(op.ID)), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": opstorage.StatusObjectID(op.ID)})
					pRouter.GetSubmission(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.GetSubmissionResponse
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Equal(tttt, opstorage.StatusObjectID(op.ID), resp.GetSubmission().ID)
					assert.Equal(tttt, definition.PresentationDefinition.ID, resp.GetSubmission().DefinitionID)
					assert.Equal(tttt, "pending", resp.Submission.Status)
				})

				ttt.Run("Create well formed submission returns operation", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					request := createSubmissionRequest(tttt, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderSigner, holderDID)

					value := newRequestValue(tttt, request)
					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.CreateSubmission(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.Operation
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Contains(tttt, resp.ID, "presentations/submissions/")
					assert.False(tttt, resp.Done)
					assert.Zero(tttt, resp.Result)
				})

				ttt.Run("Review submission returns approved submission", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					submissionOp := createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					request := router.ReviewSubmissionRequest{
						Approved: true,
						Reason:   "because I want to",
					}

					value := newRequestValue(tttt, request)
					createdID := opstorage.StatusObjectID(submissionOp.ID)
					req := httptest.NewRequest(
						http.MethodPut,
						fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", createdID),
						value)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.ReviewSubmission(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.ReviewSubmissionResponse
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Equal(tttt, "because I want to", resp.Reason)
					assert.NotEmpty(tttt, resp.GetSubmission().ID)
					assert.Equal(tttt, "approved", resp.Status)
					assert.Equal(tttt, definition.PresentationDefinition.ID, resp.GetSubmission().DefinitionID)
				})

				ttt.Run("Review submission twice fails", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					submissionOp := createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
					createdID := opstorage.StatusObjectID(submissionOp.ID)
					_ = reviewSubmission(tttt, pRouter, createdID)

					request := router.ReviewSubmissionRequest{
						Approved: true,
						Reason:   "because I want to review again",
					}

					value := newRequestValue(tttt, request)
					req := httptest.NewRequest(
						http.MethodPut,
						fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", createdID),
						value)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.ReviewSubmission(c)
					assert.Contains(tttt, w.Body.String(), "operation already marked as done")
				})

				ttt.Run("List submissions returns empty when there are none", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, _ := setupPresentationRouter(tttt, s)

					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", nil)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.ListSubmissions(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Empty(tttt, resp.Submissions)
				})

				ttt.Run("List submissions invalid page size fails", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, _ := setupPresentationRouter(tttt, s)

					w := httptest.NewRecorder()
					badParams := url.Values{
						"pageSize": []string{"-1"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+badParams.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, badParams)
					pRouter.ListSubmissions(c)

					assert.Contains(tttt, w.Body.String(), "'pageSize' must be greater than 0")
				})

				ttt.Run("List submissions made up token fails", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, _ := setupPresentationRouter(tttt, s)

					w := httptest.NewRecorder()
					badParams := url.Values{
						"pageSize":  []string{"1"},
						"pageToken": []string{"made up token"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+badParams.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, badParams)
					pRouter.ListSubmissions(c)

					assert.Contains(tttt, w.Body.String(), "token value cannot be decoded")
				})

				ttt.Run("List submissions pagination", func(tttt *testing.T) {
					// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
					if strings.Contains(test.Name, "Redis") {
						tttt.Skip("skipping pagination test for Redis")
					}
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)

					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					_ = createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					mrTeeSigner, mrTeeDID := getSigner(tttt)
					_ = createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "Mr. T",
							"dateOfBirth":    "1999-01-02",
							"familyName":     "Mister",
							"givenName":      "Tee",
							"id":             "did:web:mrt.com"})), mrTeeDID, mrTeeSigner)

					w := httptest.NewRecorder()
					params := url.Values{
						"pageSize": []string{"1"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+params.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, params)

					pRouter.ListSubmissions(c)

					var listSubmissionResponse router.ListSubmissionResponse
					err := json.NewDecoder(w.Body).Decode(&listSubmissionResponse)
					assert.NoError(tttt, err)
					assert.NotEmpty(tttt, listSubmissionResponse.NextPageToken)
					assert.Len(tttt, listSubmissionResponse.Submissions, 1)

					w = httptest.NewRecorder()
					params["pageToken"] = []string{listSubmissionResponse.NextPageToken}
					req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+params.Encode(), nil)
					c = newRequestContextWithURLValues(w, req, params)

					pRouter.ListSubmissions(c)

					var listSubmissionsResponse2 router.ListSubmissionResponse
					err = json.NewDecoder(w.Body).Decode(&listSubmissionsResponse2)
					assert.NoError(tttt, err)
					assert.Empty(tttt, listSubmissionsResponse2.NextPageToken)
					assert.Len(tttt, listSubmissionsResponse2.Submissions, 1)
				})

				ttt.Run("List submissions pagination change query between calls returns error", func(tttt *testing.T) {
					// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
					if strings.Contains(test.Name, "Redis") {
						tttt.Skip("skipping pagination test for Redis")
					}
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)

					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					_ = createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					mrTeeSigner, mrTeeDID := getSigner(tttt)
					_ = createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "Mr. T",
							"dateOfBirth":    "1999-01-02",
							"familyName":     "Mister",
							"givenName":      "Tee",
							"id":             "did:web:mrt.com"})), mrTeeDID, mrTeeSigner)

					w := httptest.NewRecorder()
					params := url.Values{
						"pageSize": []string{"1"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+params.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, params)

					pRouter.ListSubmissions(c)

					var listSubmissionResponse router.ListSubmissionResponse
					err := json.NewDecoder(w.Body).Decode(&listSubmissionResponse)
					assert.NoError(tttt, err)
					assert.NotEmpty(tttt, listSubmissionResponse.NextPageToken)
					assert.Len(tttt, listSubmissionResponse.Submissions, 1)

					w = httptest.NewRecorder()
					params["pageToken"] = []string{listSubmissionResponse.NextPageToken}
					params["filter"] = []string{"status=\"pending\""}
					req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+params.Encode(), nil)
					c = newRequestContextWithURLValues(w, req, params)

					pRouter.ListSubmissions(c)
					assert.Equal(tttt, http.StatusBadRequest, w.Result().StatusCode)
					assert.Contains(tttt, w.Body.String(), "page token must be for the same query")
				})

				ttt.Run("List submissions returns many submissions", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					op := createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					mrTeeSigner, mrTeeDID := getSigner(tttt)
					op2 := createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "Mr. T",
							"dateOfBirth":    "1999-01-02",
							"familyName":     "Mister",
							"givenName":      "Tee",
							"id":             "did:web:mrt.com"})), mrTeeDID, mrTeeSigner)

					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", nil)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.ListSubmissions(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Len(tttt, resp.Submissions, 2)

					expectedSubmissions := []model.Submission{
						{
							Status: "pending",
							VerifiablePresentation: &credential.VerifiablePresentation{
								Context: []any{"https://www.w3.org/2018/credentials/v1"},
								Holder:  holderDID.String(),
								Type:    []any{"VerifiablePresentation"},
							},
						},
						{
							Status: "pending",
							VerifiablePresentation: &credential.VerifiablePresentation{
								Context: []any{"https://www.w3.org/2018/credentials/v1"},
								Holder:  mrTeeDID.String(),
								Type:    []any{"VerifiablePresentation"},
							},
						},
					}
					diff := cmp.Diff(expectedSubmissions, resp.Submissions,
						cmpopts.IgnoreFields(credential.VerifiablePresentation{}, "ID", "VerifiableCredential", "PresentationSubmission"),
						cmpopts.SortSlices(func(l, r model.Submission) bool {
							return l.VerifiablePresentation.Holder < r.VerifiablePresentation.Holder
						}),
					)
					if diff != "" {
						tttt.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
					}
					assert.Len(tttt, resp.Submissions[0].VerifiablePresentation.VerifiableCredential, 1)
					assert.Len(tttt, resp.Submissions[1].VerifiablePresentation.VerifiableCredential, 1)

					assert.ElementsMatch(tttt,
						[]string{
							opstorage.StatusObjectID(op.ID),
							opstorage.StatusObjectID(op2.ID)},
						[]string{
							resp.Submissions[0].GetSubmission().ID,
							resp.Submissions[1].GetSubmission().ID,
						})
					assert.Equal(tttt,
						[]string{
							definition.PresentationDefinition.ID,
							definition.PresentationDefinition.ID,
						},
						[]string{
							resp.Submissions[0].GetSubmission().DefinitionID,
							resp.Submissions[1].GetSubmission().DefinitionID,
						})
				})

				ttt.Run("bad filter returns error", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, _ := setupPresentationRouter(tttt, s)

					query := url.QueryEscape("im a baaad filter that's trying to break a lot of stuff")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions?filter=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"filter": query})
					pRouter.ListSubmissions(c)
					assert.Contains(tttt, w.Body.String(), "invalid filter")
				})

				ttt.Run("List submissions filters based on status", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					op := createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					query := url.QueryEscape("status=\"pending\"")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions?filter=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"filter": query})
					pRouter.ListSubmissions(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))

					expectedSubmissions := []model.Submission{
						{
							Status: "pending",
							VerifiablePresentation: &credential.VerifiablePresentation{
								Context: []any{"https://www.w3.org/2018/credentials/v1"},
								Holder:  holderDID.String(),
								Type:    []any{"VerifiablePresentation"},
							},
						},
					}
					diff := cmp.Diff(expectedSubmissions, resp.Submissions,
						cmpopts.IgnoreFields(credential.VerifiablePresentation{}, "ID", "PresentationSubmission", "VerifiableCredential"),
						cmpopts.SortSlices(func(l, r model.Submission) bool {
							return l.VerifiablePresentation.Holder < r.VerifiablePresentation.Holder
						}),
					)
					if diff != "" {
						tttt.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
					}

					assert.Len(tttt, resp.Submissions, 1)
					assert.Len(tttt, resp.Submissions[0].VerifiablePresentation.VerifiableCredential, 1)
					assert.Equal(tttt, opstorage.StatusObjectID(op.ID), resp.Submissions[0].GetSubmission().ID)
					assert.Equal(tttt, definition.PresentationDefinition.ID, resp.Submissions[0].GetSubmission().DefinitionID)
				})

				ttt.Run("List submissions filter returns empty when status does not match", func(tttt *testing.T) {
					s := test.ServiceStorage(tttt)
					pRouter, didService := setupPresentationRouter(tttt, s)
					authorDID := createDID(tttt, didService)

					holderSigner, holderDID := getSigner(tttt)
					definition := createPresentationDefinition(tttt, pRouter)
					_ = createSubmission(tttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					query := url.QueryEscape(`status="done"`)
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions?filter=%s", query), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"filter": query})
					pRouter.ListSubmissions(c)
					assert.True(tttt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(tttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Empty(tttt, resp.Submissions)
				})
			})
		})
	}
}

func createPresentationRequest(t *testing.T, pRouter *router.PresentationRouter, definitionID string, issuerDID didsdk.Document) router.CreateRequestResponse {
	request := router.CreateRequestRequest{
		CommonCreateRequestRequest: &router.CommonCreateRequestRequest{
			IssuerDID:            issuerDID.ID,
			VerificationMethodID: issuerDID.VerificationMethod[0].ID,
			CallbackURL:          "my_callback_url",
		},
		PresentationDefinitionID: definitionID,
	}
	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/requests", value)
	w := httptest.NewRecorder()
	c := newRequestContext(w, req)
	pRouter.CreateRequest(c)
	require.True(t, util.Is2xxResponse(w.Code))

	var resp router.CreateRequestResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func setupPresentationRouter(t *testing.T, s storage.ServiceStorage) (*router.PresentationRouter, *did.Service) {
	keyStoreService, _ := testKeyStoreService(t, s)
	didService, _ := testDIDService(t, s, keyStoreService, nil)
	schemaService := testSchemaService(t, s, keyStoreService, didService)

	service, err := presentation.NewPresentationService(s, didService.GetResolver(), schemaService, keyStoreService)
	assert.NoError(t, err)

	pRouter, err := router.NewPresentationRouter(service)
	assert.NoError(t, err)
	return pRouter, didService
}

func createDID(t *testing.T, didService *did.Service) *did.CreateDIDResponse {
	creatorDID, err := didService.CreateDIDByMethod(context.Background(), did.CreateDIDRequest{
		Method:  didsdk.KeyMethod,
		KeyType: crypto.Ed25519,
	})
	require.NoError(t, err)
	return creatorDID
}

func createSubmission(t *testing.T, pRouter *router.PresentationRouter, definitionID string, requesterDID string,
	vc credential.VerifiableCredential, holderDID key.DIDKey, holderSigner jwx.Signer) router.Operation {
	request := createSubmissionRequest(t, definitionID, requesterDID, vc, holderSigner, holderDID)

	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
	w := httptest.NewRecorder()
	c := newRequestContext(w, req)
	pRouter.CreateSubmission(c)
	require.True(t, util.Is2xxResponse(w.Code))

	var resp router.Operation
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func createSubmissionRequest(t *testing.T, definitionID, requesterDID string, vc credential.VerifiableCredential,
	holderSigner jwx.Signer, holderDID key.DIDKey) router.CreateSubmissionRequest {
	issuerSigner, didKey := getSigner(t)
	vc.Issuer = didKey.String()
	vcData, err := integrity.SignVerifiableCredentialJWT(issuerSigner, vc)
	require.NoError(t, err)
	ps := exchange.PresentationSubmission{
		ID:           uuid.NewString(),
		DefinitionID: definitionID,
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:     "wa_driver_license",
				Format: string(exchange.JWTVPTarget),
				Path:   "$.verifiableCredential[0]",
			},
		},
	}

	vp := credential.VerifiablePresentation{
		Context:                []string{credential.VerifiableCredentialsLinkedDataContext},
		ID:                     uuid.NewString(),
		Holder:                 holderDID.String(),
		Type:                   []string{credential.VerifiablePresentationType},
		PresentationSubmission: ps,
		VerifiableCredential:   []any{keyaccess.JWT(vcData)},
	}

	signed, err := integrity.SignVerifiablePresentationJWT(holderSigner, integrity.JWTVVPParameters{Audience: []string{requesterDID}}, vp)
	require.NoError(t, err)

	request := router.CreateSubmissionRequest{SubmissionJWT: keyaccess.JWT(signed)}
	return request
}

func VerifiableCredential(options ...VCOption) credential.VerifiableCredential {
	vc := credential.VerifiableCredential{
		Context:        []string{credential.VerifiableCredentialsLinkedDataContext},
		ID:             uuid.NewString(),
		Type:           []string{credential.VerifiableCredentialType},
		Issuer:         "did:key:z4oJ8bFEFv7E3omhuK5LrAtL29Nmd8heBey9HtJCSvodSb7nrfaMrd6zb7fjYSRxrfSgBSDeM6Bs59KRKFgXSDWJcfcjs",
		IssuanceDate:   "2022-11-07T21:28:57Z",
		ExpirationDate: "2051-10-05T14:48:00.000Z",
		CredentialSubject: credential.CredentialSubject{
			"additionalName": "McLovin",
			"dateOfBirth":    "1987-01-02",
			"familyName":     "Andres",
			"givenName":      "Uribe",
			"id":             "did:web:andresuribe.com",
		},
	}
	for _, o := range options {
		o(&vc)
	}
	return vc
}

func WithCredentialSubject(subject credential.CredentialSubject) VCOption {
	return func(vc *credential.VerifiableCredential) {
		vc.CredentialSubject = subject
	}
}

type VCOption func(verifiableCredential *credential.VerifiableCredential)

type DefinitionOption func(*router.CreatePresentationDefinitionRequest)

func WithInputDescriptors(inputDescriptors []exchange.InputDescriptor) DefinitionOption {
	return func(r *router.CreatePresentationDefinitionRequest) {
		r.InputDescriptors = inputDescriptors
	}
}

func createPresentationDefinition(t *testing.T, pRouter *router.PresentationRouter, opts ...DefinitionOption) router.CreatePresentationDefinitionResponse {
	request := router.CreatePresentationDefinitionRequest{
		Name:    "name",
		Purpose: "purpose",
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID:      "wa_driver_license",
				Name:    "washington state business license",
				Purpose: "some testing stuff",
				Format:  nil,
				Constraints: &exchange.Constraints{
					Fields: []exchange.Field{
						{
							ID: "date_of_birth",
							Path: []string{
								"$.credentialSubject.dateOfBirth",
								"$.credentialSubject.dob",
								"$.vc.credentialSubject.dateOfBirth",
								"$.vc.credentialSubject.dob",
							},
						},
					},
				},
			},
		},
	}
	for _, o := range opts {
		o(&request)
	}
	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
	w := httptest.NewRecorder()
	c := newRequestContext(w, req)
	pRouter.CreateDefinition(c)
	require.True(t, util.Is2xxResponse(w.Code))

	var resp router.CreatePresentationDefinitionResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func getSigner(t *testing.T) (jwx.Signer, key.DIDKey) {
	private, didKey, err := key.GenerateDIDKey(crypto.P256)
	require.NoError(t, err)

	expanded, err := didKey.Expand()
	require.NoError(t, err)

	signer, err := jwx.NewJWXSigner(didKey.String(), expanded.VerificationMethod[0].ID, private)
	require.NoError(t, err)

	return *signer, *didKey
}
