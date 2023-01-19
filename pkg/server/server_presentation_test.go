package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
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

	t.Run("Create, Get, and Delete PresentationDefinition", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(tt, s)

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
			assert.NoError(tt, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

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

			assert.NoError(tt, pRouter.ListDefinitions(newRequestContext(), w, req))

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
			assert.NoError(t, pRouter.DeletePresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))
		}
		{
			// And we cannot get the PD after it's been deleted.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.Error(tt, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))
		}
	})

	t.Run("List returns empty", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(tt, s)
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
		w := httptest.NewRecorder()

		assert.NoError(tt, pRouter.ListDefinitions(newRequestContext(), w, req))

		var resp router.ListDefinitionsResponse
		assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
		assert.Empty(tt, resp.Definitions)
	})

	t.Run("List returns many definitions", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(tt, s)
		def1 := createPresentationDefinition(tt, pRouter)
		def2 := createPresentationDefinition(tt, pRouter)

		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/definitions", nil)
		w := httptest.NewRecorder()

		assert.NoError(tt, pRouter.ListDefinitions(newRequestContext(), w, req))

		var resp router.ListDefinitionsResponse
		assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
		assert.Len(tt, resp.Definitions, 2)
		assert.ElementsMatch(tt, resp.Definitions, []*exchange.PresentationDefinition{
			&def1.PresentationDefinition,
			&def2.PresentationDefinition,
		})
	})

	t.Run("Create returns error without input descriptors", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(tt, s)
		request := router.CreatePresentationDefinitionRequest{}
		value := newRequestValue(tt, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
		w := httptest.NewRecorder()

		err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)

		assert.Error(t, err)
	})

	t.Run("Get without an ID returns error", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(tt, s)
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()

		assert.Error(tt, pRouter.GetPresentationDefinition(newRequestContext(), w, req))
	})

	t.Run("Delete without an ID returns error", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter := setupPresentationRouter(tt, s)

		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(tt, pRouter.DeletePresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})

	t.Run("Submission endpoints", func(tt *testing.T) {

		tt.Run("Get non-existing ID returns error", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions/myrandomid", nil)
			w := httptest.NewRecorder()
			assert.Error(ttt, pRouter.GetSubmission(newRequestContext(), w, req))
		})

		tt.Run("Get returns submission after creation", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(ttt, pRouter)
			op := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderDID, holderSigner)

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s", opstorage.StatusObjectID(op.ID)), nil)
			w := httptest.NewRecorder()

			assert.NoError(ttt, pRouter.GetSubmission(newRequestContextWithParams(map[string]string{"id": opstorage.StatusObjectID(op.ID)}), w, req))

			var resp router.GetSubmissionResponse
			assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(ttt, opstorage.StatusObjectID(op.ID), resp.GetSubmission().ID)
			assert.Equal(ttt, definition.PresentationDefinition.ID, resp.GetSubmission().DefinitionID)
			assert.Equal(ttt, "pending", resp.Submission.Status)
		})

		tt.Run("Create well formed submission returns operation", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(ttt, pRouter)
			request := createSubmissionRequest(ttt, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderSigner, holderDID)

			value := newRequestValue(ttt, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.CreateSubmission(newRequestContext(), w, req)

			require.NoError(ttt, err)
			var resp router.Operation
			assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
			assert.Contains(ttt, resp.ID, "presentations/submissions/")
			assert.False(ttt, resp.Done)
			assert.Zero(ttt, resp.Result)
		})

		tt.Run("Review submission returns approved submission", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(ttt, pRouter)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

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

			err = pRouter.ReviewSubmission(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

			assert.NoError(ttt, err)
			var resp router.ReviewSubmissionResponse
			assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(ttt, "because I want to", resp.Reason)
			assert.NotEmpty(ttt, resp.GetSubmission().ID)
			assert.Equal(ttt, "approved", resp.Status)
			assert.Equal(ttt, definition.PresentationDefinition.ID, resp.GetSubmission().DefinitionID)
		})

		tt.Run("Review submission twice fails", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(ttt, pRouter)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)
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

			err = pRouter.ReviewSubmission(newRequestContextWithParams(map[string]string{"id": createdID}), w, req)

			assert.Error(ttt, err)
			assert.Contains(ttt, err.Error(), "operation already marked as done")
		})

		tt.Run("List submissions returns empty when there are none", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			request := router.ListSubmissionRequest{}

			value := newRequestValue(ttt, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(ttt, err)
			var resp router.ListSubmissionResponse
			assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(ttt, resp.Submissions)
		})

		tt.Run("List submissions returns many submissions", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(t, pRouter)
			op := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderDID, holderSigner)

			mrTeeSigner, mrTeeDID := getSigner(ttt)
			op2 := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mr. T",
					"dateOfBirth":    "1999-01-02",
					"familyName":     "Mister",
					"givenName":      "Tee",
					"id":             "did:web:mrt.com"})), mrTeeDID, mrTeeSigner)

			request := router.ListSubmissionRequest{}

			value := newRequestValue(ttt, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(ttt, err)
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
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)
			request := router.ListSubmissionRequest{
				Filter: `im a baaad filter that's trying to break a lot of stuff'`,
			}

			value := newRequestValue(ttt, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.Error(ttt, err)
		})

		tt.Run("List submissions filters based on status", func(ttt *testing.T) {
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(ttt, pRouter)
			op := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderDID, holderSigner)

			request := router.ListSubmissionRequest{
				Filter: `status="pending"`,
			}

			value := newRequestValue(ttt, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(ttt, err)
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
			s := setupTestDB(ttt)
			pRouter := setupPresentationRouter(ttt, s)

			holderSigner, holderDID := getSigner(ttt)
			definition := createPresentationDefinition(ttt, pRouter)
			_ = createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderDID, holderSigner)

			request := router.ListSubmissionRequest{
				Filter: `status = "done"`,
			}

			value := newRequestValue(ttt, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(ttt, err)
			var resp router.ListSubmissionResponse
			assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))

			assert.Empty(ttt, resp.Submissions)
		})
	})

}

func setupPresentationRouter(t *testing.T, s storage.ServiceStorage) *router.PresentationRouter {
	keyStoreService := testKeyStoreService(t, s)
	didService := testDIDService(t, s, keyStoreService)
	schemaService := testSchemaService(t, s, keyStoreService, didService)

	service, err := presentation.NewPresentationService(config.PresentationServiceConfig{}, s, didService.GetResolver(), schemaService)
	assert.NoError(t, err)

	pRouter, err := router.NewPresentationRouter(service)
	assert.NoError(t, err)
	return pRouter
}

func createSubmission(t *testing.T, pRouter *router.PresentationRouter, definitionID string, vc credential.VerifiableCredential, holderDID did.DIDKey, holderSigner crypto.JWTSigner) router.Operation {
	request := createSubmissionRequest(t, definitionID, vc, holderSigner, holderDID)

	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
	w := httptest.NewRecorder()

	err := pRouter.CreateSubmission(newRequestContext(), w, req)

	require.NoError(t, err)
	var resp router.Operation
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func createSubmissionRequest(t *testing.T, definitionID string, vc credential.VerifiableCredential, holderSigner crypto.JWTSigner, holderDID did.DIDKey) router.CreateSubmissionRequest {
	issuerSigner, didKey := getSigner(t)
	vc.Issuer = didKey.String()
	vcData, err := signing.SignVerifiableCredentialJWT(issuerSigner, vc)
	assert.NoError(t, err)
	ps := exchange.PresentationSubmission{
		ID:           uuid.NewString(),
		DefinitionID: definitionID,
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:         "wa_driver_license",
				Format:     string(exchange.JWTVPTarget),
				Path:       "$.verifiableCredential[0]",
				PathNested: nil,
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
		Proof:                  nil,
	}

	signed, err := signing.SignVerifiablePresentationJWT(holderSigner, vp)
	assert.NoError(t, err)

	request := router.CreateSubmissionRequest{SubmissionJWT: keyaccess.JWT(signed)}
	return request
}

func VerifiableCredential(options ...VCOption) credential.VerifiableCredential {
	vc := credential.VerifiableCredential{
		Context:          []string{credential.VerifiableCredentialsLinkedDataContext},
		ID:               uuid.NewString(),
		Type:             []string{credential.VerifiableCredentialType},
		Issuer:           "did:key:z4oJ8bFEFv7E3omhuK5LrAtL29Nmd8heBey9HtJCSvodSb7nrfaMrd6zb7fjYSRxrfSgBSDeM6Bs59KRKFgXSDWJcfcjs",
		IssuanceDate:     "2022-11-07T21:28:57Z",
		ExpirationDate:   "2051-10-05T14:48:00.000Z",
		CredentialStatus: nil,
		CredentialSubject: credential.CredentialSubject{
			"additionalName": "Mclovin",
			"dateOfBirth":    "1987-01-02",
			"familyName":     "Andres",
			"givenName":      "Uribe",
			"id":             "did:web:andresuribe.com",
		},
		CredentialSchema: nil,
		RefreshService:   nil,
		TermsOfUse:       nil,
		Evidence:         nil,
		Proof:            nil,
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
		Name:                   "name",
		Purpose:                "purpose",
		Format:                 nil,
		SubmissionRequirements: nil,
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

	assert.NoError(t, pRouter.CreatePresentationDefinition(newRequestContext(), w, req))
	var resp router.CreatePresentationDefinitionResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func getSigner(t *testing.T) (crypto.JWTSigner, did.DIDKey) {
	private, didKey, err := did.GenerateDIDKey(crypto.P256)
	assert.NoError(t, err)

	signer, err := crypto.NewJWTSigner(didKey.String(), private)
	assert.NoError(t, err)

	return *signer, *didKey
}
