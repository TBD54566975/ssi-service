package server

import (
	"fmt"
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
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"github.com/tbd54566975/ssi-service/pkg/service/presentation"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
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

	t.Run("Create, Get, and Delete PresentationDefinition", func(t *testing.T) {
		s, err := storage.NewBoltDB()
		assert.NoError(t, err)
		pRouter := setupPresentationRouter(t, s)

		var createdID string
		{
			// Create returns the expected PD.
			request := router.CreatePresentationDefinitionRequest{
				Name:                   "name",
				Purpose:                "purpose",
				Format:                 nil,
				SubmissionRequirements: nil,
				InputDescriptors:       inputDescriptors,
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
			w := httptest.NewRecorder()

			err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)
			assert.NoError(t, err)

			var resp router.CreatePresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
				t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
			}

			w.Flush()
			createdID = resp.PresentationDefinition.ID
		}
		{
			// We can get the PD after it's created.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))

			var resp router.GetPresentationDefinitionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, createdID, resp.PresentationDefinition.ID)
			if diff := cmp.Diff(*pd, resp.PresentationDefinition, cmpopts.IgnoreFields(exchange.PresentationDefinition{}, "ID")); diff != "" {
				t.Errorf("PresentationDefinition mismatch (-want +got):\n%s", diff)
			}

			w.Flush()
		}
		{
			// The PD can be deleted.
			req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.NoError(t, pRouter.DeletePresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))
			w.Flush()
		}
		{
			// And we cannot get the PD after it's been deleted.
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", createdID), nil)
			w := httptest.NewRecorder()
			assert.Error(t, pRouter.GetPresentationDefinition(newRequestContextWithParams(map[string]string{"id": createdID}), w, req))
		}
	})

	t.Run("Create returns error without input descriptors", func(t *testing.T) {
		s, err := storage.NewBoltDB()
		assert.NoError(t, err)
		pRouter := setupPresentationRouter(t, s)
		request := router.CreatePresentationDefinitionRequest{}
		value := newRequestValue(t, request)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/definitions", value)
		w := httptest.NewRecorder()

		err = pRouter.CreatePresentationDefinition(newRequestContext(), w, req)

		assert.Error(t, err)
	})

	t.Run("Get without an ID returns error", func(t *testing.T) {
		s, err := storage.NewBoltDB()
		assert.NoError(t, err)
		pRouter := setupPresentationRouter(t, s)
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()

		assert.Error(t, pRouter.GetPresentationDefinition(newRequestContext(), w, req))
	})

	t.Run("Delete without an ID returns error", func(t *testing.T) {
		s, err := storage.NewBoltDB()
		assert.NoError(t, err)
		pRouter := setupPresentationRouter(t, s)

		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("https://ssi-service.com/v1/presentations/definitions/%s", pd.ID), nil)
		w := httptest.NewRecorder()
		assert.Error(t, pRouter.DeletePresentationDefinition(newRequestContext(), w, req))
		w.Flush()
	})

	t.Run("Submission endpoints", func(t *testing.T) {

		t.Run("Get non-existing ID returns error", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions/myrandomid", nil)
			w := httptest.NewRecorder()
			assert.Error(t, pRouter.GetSubmission(newRequestContext(), w, req))
		})

		t.Run("Get returns submission after creation", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			op := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderDID, holderSigner)

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s", operation.SubmissionID(op.ID)), nil)
			w := httptest.NewRecorder()

			assert.NoError(t, pRouter.GetSubmission(newRequestContextWithParams(map[string]string{"id": operation.SubmissionID(op.ID)}), w, req))

			var resp router.GetSubmissionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Equal(t, operation.SubmissionID(op.ID), resp.Submission.ID)
			assert.Equal(t, definition.PresentationDefinition.ID, resp.Submission.DefinitionID)
			assert.Equal(t, "pending", resp.Submission.Status)
		})

		t.Run("Create well formed submission returns operation", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			request := createSubmissionRequest(t, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderSigner, holderDID)

			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.CreateSubmission(newRequestContext(), w, req)

			require.NoError(t, err)
			var resp router.Operation
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Contains(t, resp.ID, "presentations/submissions/")
			assert.False(t, resp.Done)
			assert.Zero(t, resp.Result)
		})

		t.Run("List submissions returns empty when there are none", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			request := router.ListSubmissionRequest{}

			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(t, err)
			var resp router.ListSubmissionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Submissions)
		})

		t.Run("List submissions returns many submissions", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			op := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mclovin",
					"dateOfBirth":    "1987-01-02",
					"familyName":     "Andres",
					"givenName":      "Uribe",
					"id":             "did:web:andresuribe.com",
				})), holderDID, holderSigner)

			mrTeeSigner, mrTeeDID := getSigner(t)
			op2 := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
				WithCredentialSubject(credential.CredentialSubject{
					"additionalName": "Mr. T",
					"dateOfBirth":    "1999-01-02",
					"familyName":     "Mister",
					"givenName":      "Tee",
					"id":             "did:web:mrt.com"})), mrTeeDID, mrTeeSigner)

			request := router.ListSubmissionRequest{}

			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(t, err)
			var resp router.ListSubmissionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Len(t, resp.Submissions, 2)

			expectedSubmissions := []presentation.Submission{
				{
					Status: "pending",
					PresentationSubmission: &exchange.PresentationSubmission{
						ID:           operation.SubmissionID(op.ID),
						DefinitionID: definition.PresentationDefinition.ID,
					},
				},
				{
					Status: "pending",
					PresentationSubmission: &exchange.PresentationSubmission{
						ID:           operation.SubmissionID(op2.ID),
						DefinitionID: definition.PresentationDefinition.ID,
					},
				},
			}
			diff := cmp.Diff(expectedSubmissions, resp.Submissions,
				cmpopts.IgnoreFields(exchange.PresentationSubmission{}, "DescriptorMap"),
				cmpopts.SortSlices(func(l, r presentation.Submission) bool {
					return l.PresentationSubmission.ID < r.PresentationSubmission.ID
				}),
			)
			if diff != "" {
				t.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
			}
		})

		t.Run("bad filter returns error", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)
			request := router.ListSubmissionRequest{
				Filter: `im a baaad filter that's trying to break a lot of stuff'`,
			}

			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.Error(t, err)
		})

		t.Run("List submissions filters based on status", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
			op := createSubmission(t, pRouter, definition.PresentationDefinition.ID, VerifiableCredential(
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

			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(t, err)
			var resp router.ListSubmissionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

			expectedSubmissions := []presentation.Submission{
				{
					Status: "pending",
					PresentationSubmission: &exchange.PresentationSubmission{
						ID:           operation.SubmissionID(op.ID),
						DefinitionID: definition.PresentationDefinition.ID,
					},
				},
			}
			diff := cmp.Diff(expectedSubmissions, resp.Submissions,
				cmpopts.IgnoreFields(exchange.PresentationSubmission{}, "DescriptorMap"),
				cmpopts.SortSlices(func(l, r presentation.Submission) bool {
					return l.PresentationSubmission.ID < r.PresentationSubmission.ID
				}),
			)
			if diff != "" {
				t.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
			}
		})

		t.Run("List submissions filter returns empty when status does not match", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			definition := createPresentationDefinition(t, pRouter)
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

			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/presentations/submissions", value)
			w := httptest.NewRecorder()

			err = pRouter.ListSubmissions(newRequestContext(), w, req)

			require.NoError(t, err)
			var resp router.ListSubmissionResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

			assert.Empty(t, resp.Submissions)
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

	t.Cleanup(func() {
		_ = s.Close()
		_ = os.Remove(storage.DBFile)
	})
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
		VerifiableCredential:   []interface{}{keyaccess.JWT(vcData)},
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
		Type:             []string{credential.VerifiablePresentationType},
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

func createPresentationDefinition(t *testing.T, pRouter *router.PresentationRouter) router.CreatePresentationDefinitionResponse {
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
