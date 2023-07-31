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
			t.Run("Marks operation as done after reviewing submission", func(tt *testing.T) {
				s := test.ServiceStorage(tt)
				pRouter, didService := setupPresentationRouter(tt, s)
				authorDID := createDID(tt, didService)
				opRouter := setupOperationsRouter(tt, s)

				holderSigner, holderDID := getSigner(tt)
				definition := createPresentationDefinition(t, pRouter)
				submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
				sub := reviewSubmission(t, pRouter, opstorage.StatusObjectID(submissionOp.ID))

				createdID := submissionOp.ID
				req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
				w := httptest.NewRecorder()

				c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
				opRouter.GetOperation(c)
				assert.True(tt, util.Is2xxResponse(w.Code))

				var resp router.Operation
				assert.NoError(tt, json.NewDecoder(w.Body).Decode(&resp))
				assert.True(tt, resp.Done)
				assert.Empty(tt, resp.Result.Error)
				data, err := json.Marshal(sub)
				assert.NoError(tt, err)

				var responseAsMap map[string]any
				assert.NoError(tt, json.Unmarshal(data, &responseAsMap))
				assert.Equal(tt, responseAsMap, resp.Result.Response)
			})

			t.Run("GetOperation", func(tt *testing.T) {
				tt.Run("Returns operation after submission", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)
					opRouter := setupOperationsRouter(ttt, s)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					submissionOp := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					createdID := submissionOp.ID
					req := httptest.NewRequest(
						http.MethodPut,
						fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
						nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					opRouter.GetOperation(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.Operation
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.False(ttt, resp.Done)
					assert.Contains(ttt, resp.ID, "presentations/submissions/")
				})

				tt.Run("Returns error when id doesn't exist", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					opRouter := setupOperationsRouter(ttt, s)

					req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/operations/some_fake_id", nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": "some_fake_id"})
					opRouter.GetOperation(c)
					assert.Contains(ttt, w.Body.String(), "operation not found with id")
				})
			})

			t.Run("ListOperations", func(tt *testing.T) {
				tt.Run("Returns empty when no operations stored", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					opRouter := setupOperationsRouter(ttt, s)

					query := url.QueryEscape("presentations/submissions")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"parent": query})
					opRouter.ListOperations(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListOperationsResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Empty(ttt, resp.Operations)
				})

				tt.Run("Returns one operation for every submission", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)
					opRouter := setupOperationsRouter(ttt, s)

					def := createPresentationDefinition(ttt, pRouter)
					holderSigner, holderDID := getSigner(ttt)
					submissionOp := createSubmission(ttt, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					holderSigner2, holderDID2 := getSigner(ttt)
					submissionOp2 := createSubmission(ttt, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID2, holderSigner2)

					query := url.QueryEscape("presentations/submissions")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s", query), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"parent": query})
					opRouter.ListOperations(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListOperationsResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					ops := []router.Operation{submissionOp, submissionOp2}
					diff := cmp.Diff(ops, resp.Operations,
						cmpopts.IgnoreFields(exchange.PresentationSubmission{}, "DescriptorMap"),
						cmpopts.SortSlices(func(l, r router.Operation) bool {
							return l.ID < r.ID
						}),
					)
					if diff != "" {
						ttt.Errorf("Mismatch on submissions (-want +got):\n%s", diff)
					}
				})

				tt.Run("Returns operation when filtering to include", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)
					opRouter := setupOperationsRouter(ttt, s)

					def := createPresentationDefinition(ttt, pRouter)
					holderSigner, holderDID := getSigner(ttt)
					_ = createSubmission(ttt, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					queryParent := url.QueryEscape("presentations/submissions")
					queryDone := url.QueryEscape("done=false")
					req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s&filter=%s", queryParent, queryDone), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"parent": queryParent, "done": queryDone})
					opRouter.ListOperations(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.ListOperationsResponse
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.Len(ttt, resp.Operations, 1)
					assert.False(ttt, resp.Operations[0].Done)
				})

				// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
				if !strings.Contains(test.Name, "Redis") {
					tt.Run("Returns zero operations when filtering to exclude", func(ttt *testing.T) {

						s := test.ServiceStorage(ttt)
						pRouter, didService := setupPresentationRouter(ttt, s)
						authorDID := createDID(ttt, didService)
						opRouter := setupOperationsRouter(ttt, s)

						def := createPresentationDefinition(ttt, pRouter)
						holderSigner, holderDID := getSigner(ttt)
						_ = createSubmission(ttt, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

						queryParent := url.QueryEscape("presentations/submissions")
						queryDone := url.QueryEscape("done=true")
						sprintf := fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s&filter=%s", queryParent, queryDone)
						req := httptest.NewRequest(http.MethodGet, sprintf, nil)
						w := httptest.NewRecorder()

						c := newRequestContextWithParams(w, req, map[string]string{"parent": queryParent, "filter": queryDone})
						opRouter.ListOperations(c)
						assert.True(tt, util.Is2xxResponse(w.Code))

						var resp router.ListOperationsResponse
						assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
						assert.Empty(ttt, resp.Operations)
					})
				}

				// TODO: Fix pagesize issue on redis - https://github.com/TBD54566975/ssi-service/issues/538
				if !strings.Contains(test.Name, "Redis") {
					tt.Run("Returns zero operations when wrong parent is specified", func(ttt *testing.T) {

						s := test.ServiceStorage(ttt)
						pRouter, didService := setupPresentationRouter(ttt, s)
						authorDID := createDID(ttt, didService)
						opRouter := setupOperationsRouter(ttt, s)

						def := createPresentationDefinition(ttt, pRouter)
						holderSigner, holderDID := getSigner(ttt)
						_ = createSubmission(ttt, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

						queryParent := url.QueryEscape("/presentations/other")
						req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://ssi-service.com/v1/operations?parent=%s", queryParent), nil)
						w := httptest.NewRecorder()

						c := newRequestContextWithParams(w, req, map[string]string{"parent": queryParent})
						opRouter.ListOperations(c)
						assert.True(tt, util.Is2xxResponse(w.Code))

						var resp router.ListOperationsResponse
						assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
						assert.Empty(ttt, resp.Operations)

					})
				}
			})

			t.Run("CancelOperation", func(tt *testing.T) {
				tt.Run("Marks an operation as done", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)
					opRouter := setupOperationsRouter(ttt, s)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					submissionOp := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

					createdID := submissionOp.ID
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
					w := httptest.NewRecorder()

					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					opRouter.CancelOperation(c)
					assert.True(tt, util.Is2xxResponse(w.Code))

					var resp router.Operation
					assert.NoError(ttt, json.NewDecoder(w.Body).Decode(&resp))
					assert.True(ttt, resp.Done)
					assert.Contains(ttt, resp.Result.Response, "verifiablePresentation")
					assert.Equal(ttt, "cancelled", resp.Result.Response.(map[string]any)["status"])
				})

				tt.Run("Returns error when operation is done already", func(ttt *testing.T) {
					s := test.ServiceStorage(ttt)
					pRouter, didService := setupPresentationRouter(ttt, s)
					authorDID := createDID(ttt, didService)
					opRouter := setupOperationsRouter(ttt, s)

					holderSigner, holderDID := getSigner(ttt)
					definition := createPresentationDefinition(ttt, pRouter)
					submissionOp := createSubmission(ttt, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
					_ = reviewSubmission(ttt, pRouter, opstorage.StatusObjectID(submissionOp.ID))

					createdID := submissionOp.ID
					req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
					w := httptest.NewRecorder()
					c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
					opRouter.CancelOperation(c)
					assert.Contains(ttt, w.Body.String(), "operation already marked as done")
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
