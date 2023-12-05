package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestOperationsAPI(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Marks operation as done after reviewing submission", func(t *testing.T) {
				s := test.ServiceStorage(t)
				pRouter, didService := setupPresentationRouter(t, s)
				authorDID := createDID(t, didService)
				opRouter := setupOperationsRouter(t, s)

				holderSigner, holderDID := getSigner(t)
				definition := createPresentationDefinition(t, pRouter)
				submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
				sub := reviewSubmission(t, pRouter, opstorage.StatusObjectID(submissionOp.ID))

				createdID := submissionOp.ID
				req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
				w := httptest.NewRecorder()

				c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
				opRouter.GetOperation(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.Operation
				assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
				assert.True(t, resp.Done)
				assert.Empty(t, resp.Result.Error)
				data, err := json.Marshal(sub)
				assert.NoError(t, err)

				var responseAsMap map[string]any
				assert.NoError(t, json.Unmarshal(data, &responseAsMap))
				assert.Equal(t, responseAsMap, resp.Result.Response)
			})

			t.Run("GetOperation", func(t *testing.T) {
				t.Run("Returns operation after submission", func(t *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(t, s)
					authorDID := createDID(t, didService)
					opRouter := setupOperationsRouter(t, s)

					holderSigner, holderDID := getSigner(t)
					definition := createPresentationDefinition(t, pRouter)
					submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					createdID := submissionOp.ID
					req := httptest.NewRequest(
						http.MethodPut,
						fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
						nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					opRouter.GetOperation(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var resp router.Operation
					assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
					assert.False(t, resp.Done)
					assert.Contains(t, resp.ID, "presentations/submissions/")
				})

				t.Run("Returns error when id doesn't exist", func(t *testing.T) {
					s := test.ServiceStorage(t)
					opRouter := setupOperationsRouter(t, s)

					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/operations/some_fake_id", nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": "some_fake_id"})
					opRouter.GetOperation(c)
					assert.Contains(t, w.Body.String(), "operation not found with id")
				})
			})

			t.Run("ListOperations", func(t *testing.T) {
				t.Run("Returns empty when no operations stored", func(t *testing.T) {
					s := test.ServiceStorage(t)
					opRouter := setupOperationsRouter(t, s)

					query := url.QueryEscape("presentations/submissions")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"parent": query})
					opRouter.ListOperations(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var resp router.ListOperationsResponse
					assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
					assert.Empty(t, resp.Operations)
				})

				t.Run("Returns one operation for every submission", func(t *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(t, s)
					authorDID := createDID(t, didService)
					opRouter := setupOperationsRouter(t, s)

					def := createPresentationDefinition(t, pRouter)
					holderSigner, holderDID := getSigner(t)
					submissionOp := createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					holderSigner2, holderDID2 := getSigner(t)
					submissionOp2 := createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID2, holderSigner2)

					query := url.QueryEscape("presentations/submissions")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"parent": query})
					opRouter.ListOperations(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var resp router.ListOperationsResponse
					assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
					ops := []router.Operation{submissionOp, submissionOp2}
					diff := cmp.Diff(ops, resp.Operations,
						cmpopts.IgnoreFields(exchange.PresentationSubmission{}, "DescriptorMap"),
						cmpopts.SortSlices(func(l, r router.Operation) bool {
							return l.ID < r.ID
						}),
					)
					if diff != "" {
						t.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
					}
				})

				t.Run("Returns operation when filtering to include", func(t *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(t, s)
					authorDID := createDID(t, didService)
					opRouter := setupOperationsRouter(t, s)

					def := createPresentationDefinition(t, pRouter)
					holderSigner, holderDID := getSigner(t)
					_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					queryParent := url.QueryEscape("presentations/submissions")
					queryDone := url.QueryEscape("done=false")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s&filter=%s", queryParent, queryDone), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"parent": queryParent, "done": queryDone})
					opRouter.ListOperations(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var resp router.ListOperationsResponse
					assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
					assert.Len(t, resp.Operations, 1)
					assert.False(t, resp.Operations[0].Done)
				})

				// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
				if !strings.Contains(test.Name, "Redis") {
					t.Run("Returns zero operations when filtering to exclude", func(t *testing.T) {

						s := test.ServiceStorage(t)
						pRouter, didService := setupPresentationRouter(t, s)
						authorDID := createDID(t, didService)
						opRouter := setupOperationsRouter(t, s)

						def := createPresentationDefinition(t, pRouter)
						holderSigner, holderDID := getSigner(t)
						_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

						queryParent := url.QueryEscape("presentations/submissions")
						queryDone := url.QueryEscape("done=true")
						sprintf := fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s&filter=%s", queryParent, queryDone)
						req := httptest.NewRequest(http.MethodGet, sprintf, nil)
						w := httptest.NewRecorder()

						c := newRequestContextWithParams(w, req, map[string]string{"parent": queryParent, "filter": queryDone})
						opRouter.ListOperations(c)
						assert.True(t, util.Is2xxResponse(w.Code))

						var resp router.ListOperationsResponse
						assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
						assert.Empty(t, resp.Operations)
					})
				}

				// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
				if !strings.Contains(test.Name, "Redis") {
					t.Run("Returns zero operations when wrong parent is specified", func(t *testing.T) {

						s := test.ServiceStorage(t)
						pRouter, didService := setupPresentationRouter(t, s)
						authorDID := createDID(t, didService)
						opRouter := setupOperationsRouter(t, s)

						def := createPresentationDefinition(t, pRouter)
						holderSigner, holderDID := getSigner(t)
						_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

						queryParent := url.QueryEscape("/presentations/other")
						req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s", queryParent), nil)
						w := httptest.NewRecorder()

						c := newRequestContextWithParams(w, req, map[string]string{"parent": queryParent})
						opRouter.ListOperations(c)
						assert.True(t, util.Is2xxResponse(w.Code))

						var resp router.ListOperationsResponse
						assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
						assert.Empty(t, resp.Operations)

					})
				}
			})

			t.Run("CancelOperation", func(t *testing.T) {
				t.Run("Marks an operation as done", func(t *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(t, s)
					authorDID := createDID(t, didService)
					opRouter := setupOperationsRouter(t, s)

					holderSigner, holderDID := getSigner(t)
					definition := createPresentationDefinition(t, pRouter)
					submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					createdID := submissionOp.ID
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					opRouter.CancelOperation(c)
					assert.True(t, util.Is2xxResponse(w.Code))

					var resp router.Operation
					assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
					assert.True(t, resp.Done)
					assert.Contains(t, resp.Result.Response, "verifiablePresentation")
					assert.Equal(t, "cancelled", resp.Result.Response.(map[string]any)["status"])
				})

				t.Run("Returns error when operation is done already", func(t *testing.T) {
					s := test.ServiceStorage(t)
					pRouter, didService := setupPresentationRouter(t, s)
					authorDID := createDID(t, didService)
					opRouter := setupOperationsRouter(t, s)

					holderSigner, holderDID := getSigner(t)
					definition := createPresentationDefinition(t, pRouter)
					submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
					_ = reviewSubmission(t, pRouter, opstorage.StatusObjectID(submissionOp.ID))

					createdID := submissionOp.ID
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					opRouter.CancelOperation(c)
					assert.Contains(t, w.Body.String(), "operation already marked as done")
				})
			})
		})
	}
}

func reviewSubmission(t *testing.T, pRouter *router.PresentationRouter, submissionID string) router.ReviewSubmissionResponse {
	request := router.ReviewSubmissionRequest{
		Approved: true,
		Reason:   "because I want to",
	}

	value := newRequestValue(t, request)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", submissionID), value)
	w := httptest.NewRecorder()
	c := newRequestContextWithParams(w, req, map[string]string{"id": submissionID})
	pRouter.ReviewSubmission(c)
	assert.True(t, util.Is2xxResponse(w.Code))

	var resp router.ReviewSubmissionResponse
	assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

func setupOperationsRouter(t *testing.T, s storage.ServiceStorage) *router.OperationRouter {
	svc, err := operation.NewOperationService(s)
	assert.NoError(t, err)
	opRouter, err := router.NewOperationRouter(svc)
	assert.NoError(t, err)
	return opRouter
}
