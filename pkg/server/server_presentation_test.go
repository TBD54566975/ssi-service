package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
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

	"github.com/tbd54566975/ssi-service/config"
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
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Create, Get, and Delete PresentationDefinition", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, _ := setupPresentationRouter(tt, s)

				var createdID string
				{
					resp := createPresentationDefinition(tt, pRouter, WithInputDescriptors(inputDescriptors))
					if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
						t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
					}

					createdID = resp.PresentationDefinition.ID
				}
				{
					// We can get the PD after it's created.
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.GetDefinition(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.GetPresentationDefinitionResponse
					assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Equal(tt, createdID, resp.PresentationDefinition.ID)
					if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
						t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
					}
				}
				{
					// And it can also be listed
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.ListDefinitions(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListDefinitionsResponse
					assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Len(tt, resp.Definitions, 1)
					assert.Equal(tt, createdID, resp.Definitions[0].ID)
					if diff := cmp.Diff(pd, resp.Definitions[0], cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
						t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
					}
				}
				{
					// The PD can be deleted.
					req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.DeleteDefinition(c)
					assert.True(tt, util.Is2xxResponse(w.Code))
				}
				{
					// And we cannot get the PD after it's been deleted.
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.GetDefinition(c)
					assert.Contains(tt, w.Body.String(), "not found")
				}
			})

			t.Run("List presentation requests returns empty", func(tt *testing.T) {
				s := test.ServiceStorage(t)
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

			t.Run("List presentation requests returns many requests", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, didService := setupPresentationRouter(tt, s)
				issuerDID := createDID(tt, didService)
				def := createPresentationDefinition(tt, pRouter)
				req1 := createPresentationRequest(tt, pRouter, def.PresentationDefinition.ID, issuerDID.DID)
				req2 := createPresentationRequest(tt, pRouter, def.PresentationDefinition.ID, issuerDID.DID)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/requests", nil)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				pRouter.ListRequests(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.ListPresentationRequestsResponse
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Len(tt, resp.Requests, 2)
				assert.ElementsMatch(tt, resp.Requests, []model.Request{
					*req1.Request,
					*req2.Request,
				})
			})

			t.Run("List definitions returns empty", func(tt *testing.T) {
				s := test.ServiceStorage(t)
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

			t.Run("List definitions returns many definitions", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, _ := setupPresentationRouter(tt, s)
				def1 := createPresentationDefinition(tt, pRouter)
				def2 := createPresentationDefinition(tt, pRouter)

				req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
				w := httptest.NewRecorder()
				c := newRequestContext(w, req)
				pRouter.ListDefinitions(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.ListDefinitionsResponse
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
				assert.Len(tt, resp.Definitions, 2)
				assert.ElementsMatch(tt, resp.Definitions, []*exchange.PresentationDefinition{
					&def1.PresentationDefinition,
					&def2.PresentationDefinition,
				})
			})

			t.Run("Create returns error without input descriptors", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, _ := setupPresentationRouter(tt, s)
				request := router.CreatePresentationDefinitionRequest{}
				value := newRequestValue(tt, request)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				pRouter.CreateDefinition(c)
				assert.Contains(t, w.Body.String(), "inputDescriptors is a required field")
			})

			t.Run("Get without an ID returns error", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, _ := setupPresentationRouter(tt, s)
				req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
				w := httptest.NewRecorder()

				c := newRequestContextWithParams(w, req, map[string]string{"id": pd.ID})
				pRouter.GetDefinition(c)
				assert.Contains(t, w.Body.String(), "not found")
			})

			t.Run("Delete without an ID returns error", func(tt *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, _ := setupPresentationRouter(tt, s)

				req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
				w := httptest.NewRecorder()
				c := newRequestContextWithParams(w, req, map[string]string{"id": pd.ID})
				pRouter.DeleteDefinition(c)
				assert.Contains(t, w.Body.String(), fmt.Sprintf("could not delete presentation definition with id: %s", pd.ID))
			})

			t.Run("Submission endpoints", func(tt *testing.T) {
				tt.Run("Get non-existing ID returns error", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, _ := setupPresentationRouter(ttt, s)

					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions/myrandomid", nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": "myrandomid"})
					pRouter.GetSubmission(c)
					assert.Contains(ttt, w.Body.String(), "not found")
				})

				tt.Run("Get returns submission after creation", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					op := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
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
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.GetSubmissionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Equal(ttt, opstorage.StatusObjectID(op.ID), resp.GetSubmission().ID)
					assert.Equal(ttt, definition.PresentationDefinition.ID, resp.GetSubmission().DefinitionID)
					assert.Equal(ttt, "pending", resp.Submission.Status)
				})

				tt.Run("Create well formed submission returns operation", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					request := createSubmissionRequest(ttt, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderSigner, holderDID)

					value := newRequestValue(ttt, request)
					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.CreateSubmission(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.Operation
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Contains(ttt, resp.ID, "presentations/submissions/")
					assert.False(ttt, resp.Done)
					assert.Zero(ttt, resp.Result)
				})

				tt.Run("Review submission returns approved submission", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					request := router.ReviewSubmissionRequest{
						Approved: true,
						Reason:   "because I want to",
					}

					value := newRequestValue(ttt, request)
					createdID := opstorage.StatusObjectID(submissionOp.ID)
					req := httptest.NewRequest(
						http.MethodPut,
						fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", createdID),
						value)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.ReviewSubmission(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ReviewSubmissionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Equal(ttt, "because I want to", resp.Reason)
					assert.NotEmpty(ttt, resp.GetSubmission().ID)
					assert.Equal(ttt, "approved", resp.Status)
					assert.Equal(ttt, definition.PresentationDefinition.ID, resp.GetSubmission().DefinitionID)
				})

				tt.Run("Review submission twice fails", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
					createdID := opstorage.StatusObjectID(submissionOp.ID)
					_ = reviewSubmission(ttt, pRouter, createdID)

					request := router.ReviewSubmissionRequest{
						Approved: true,
						Reason:   "because I want to review again",
					}

					value := newRequestValue(ttt, request)
					req := httptest.NewRequest(
						http.MethodPut,
						fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", createdID),
						value)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					pRouter.ReviewSubmission(c)
					assert.Contains(ttt, w.Body.String(), "operation already marked as done")
				})

				tt.Run("List submissions returns empty when there are none", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, _ := setupPresentationRouter(ttt, s)

					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", nil)
					w := httptest.NewRecorder()

					c := newRequestContext(w, req)
					pRouter.ListSubmissions(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Empty(ttt, resp.Submissions)
				})

				tt.Run("List submissions invalid page size fails", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, _ := setupPresentationRouter(ttt, s)

					w := httptest.NewRecorder()
					badParams := url.Values{
						"pageSize": []string{"-1"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+badParams.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, badParams)
					pRouter.ListSubmissions(c)

					assert.Contains(tt, w.Body.String(), "'pageSize' must be greater than 0")
				})

				tt.Run("List submissions made up token fails", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, _ := setupPresentationRouter(ttt, s)

					w := httptest.NewRecorder()
					badParams := url.Values{
						"pageSize":  []string{"1"},
						"pageToken": []string{"made up token"},
					}
					req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+badParams.Encode(), nil)
					c := newRequestContextWithURLValues(w, req, badParams)
					pRouter.ListSubmissions(c)

					assert.Contains(tt, w.Body.String(), "token value cannot be decoded")
				})

				tt.Run("List submissions pagination", func(ttt *testing.T) {
					// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
					if strings.Contains(test.Name, "Redis") {
						ttt.Skip("skipping pagination test for Redis")
					}
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)

					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					_ = createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					mrTeeSigner, mrTeeDID := getSigner(ttt)
					_ = createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
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
					assert.NoError(tt, err)
					assert.NotEmpty(tt, listSubmissionResponse.NextPageToken)
					assert.Len(tt, listSubmissionResponse.Submissions, 1)

					w = httptest.NewRecorder()
					params["pageToken"] = []string{listSubmissionResponse.NextPageToken}
					req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+params.Encode(), nil)
					c = newRequestContextWithURLValues(w, req, params)

					pRouter.ListSubmissions(c)

					var listSubmissionsResponse2 router.ListSubmissionResponse
					err = json.NewDecoder(w.Body).Decode(&listSubmissionsResponse2)
					assert.NoError(tt, err)
					assert.Empty(tt, listSubmissionsResponse2.NextPageToken)
					assert.Len(tt, listSubmissionsResponse2.Submissions, 1)
				})

				tt.Run("List submissions pagination change query between calls returns error", func(ttt *testing.T) {
					// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
					if strings.Contains(test.Name, "Redis") {
						ttt.Skip("skipping pagination test for Redis")
					}
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)

					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					_ = createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					mrTeeSigner, mrTeeDID := getSigner(ttt)
					_ = createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
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
					assert.NoError(tt, err)
					assert.NotEmpty(tt, listSubmissionResponse.NextPageToken)
					assert.Len(tt, listSubmissionResponse.Submissions, 1)

					w = httptest.NewRecorder()
					params["pageToken"] = []string{listSubmissionResponse.NextPageToken}
					params["filter"] = []string{"status=\"pending\""}
					req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions?"+params.Encode(), nil)
					c = newRequestContextWithURLValues(w, req, params)

					pRouter.ListSubmissions(c)
					assert.Equal(tt, http.StatusBadRequest, w.Result().StatusCode)
					assert.Contains(tt, w.Body.String(), "page token must be for the same query")
				})

				tt.Run("List submissions returns many submissions", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					op := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
						WithCredentialSubject(credential.CredentialSubject{
							"additionalName": "McLovin",
							"dateOfBirth":    "1987-01-02",
							"familyName":     "Andres",
							"givenName":      "Uribe",
							"id":             "did:web:andresuribe.com",
						})), holderDID, holderSigner)

					mrTeeSigner, mrTeeDID := getSigner(ttt)
					op2 := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
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
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Len(ttt, resp.Submissions, 2)

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
						ttt.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
					}
					assert.Len(ttt, resp.Submissions[0].VerifiablePresentation.VerifiableCredential, 1)
					assert.Len(ttt, resp.Submissions[1].VerifiablePresentation.VerifiableCredential, 1)

					assert.ElementsMatch(ttt,
						[]string{
							opstorage.StatusObjectID(op.ID),
							opstorage.StatusObjectID(op2.ID)},
						[]string{
							resp.Submissions[0].GetSubmission().ID,
							resp.Submissions[1].GetSubmission().ID,
						})
					assert.Equal(ttt,
						[]string{
							definition.PresentationDefinition.ID,
							definition.PresentationDefinition.ID,
						},
						[]string{
							resp.Submissions[0].GetSubmission().DefinitionID,
							resp.Submissions[1].GetSubmission().DefinitionID,
						})
				})

				tt.Run("bad filter returns error", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, _ := setupPresentationRouter(ttt, s)

					query := url.QueryEscape("im a baaad filter that's trying to break a lot of stuff")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions?filter=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"filter": query})
					pRouter.ListSubmissions(c)
					assert.Contains(ttt, w.Body.String(), "invalid filter")
				})

				tt.Run("List submissions filters based on status", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					op := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
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
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))

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
						ttt.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
					}

					assert.Len(ttt, resp.Submissions, 1)
					assert.Len(ttt, resp.Submissions[0].VerifiablePresentation.VerifiableCredential, 1)
					assert.Equal(ttt, opstorage.StatusObjectID(op.ID), resp.Submissions[0].GetSubmission().ID)
					assert.Equal(ttt, definition.PresentationDefinition.ID, resp.Submissions[0].GetSubmission().DefinitionID)
				})

				tt.Run("List submissions filter returns empty when status does not match", func(ttt *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					_ = createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(
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
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListSubmissionResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Empty(ttt, resp.Submissions)
				})
			})
		})
	}
}

func createPresentationRequest(t *testing.T, pRouter *router.PresentationRouter, definitionID string, issuerDID didsdk.Document) router.CreateRequestResponse {
	request := router.CreateRequestRequest{
		CommonCreateRequestRequest: &router.CommonCreateRequestRequest{
			IssuerDID: issuerDID.ID,
			IssuerKID: issuerDID.VerificationMethod[0].ID,
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
	keyStoreService := testKeyStoreService(t, s)
	didService := testDIDService(t, s, keyStoreService)
	schemaService := testSchemaService(t, s, keyStoreService, didService)

	service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s, didService.GetResolver(), schemaService, keyStoreService)
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
	vcData, err := credential.SignVerifiableCredentialJWT(issuerSigner, vc)
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

	signed, err := credential.SignVerifiablePresentationJWT(holderSigner, credential.JWTVVPParameters{Audience: []string{requesterDID}}, vp)
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
