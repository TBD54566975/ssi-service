package server

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestOperationsAPI(t *testing.T) {
	t.Run("GetOperations", func(t *testing.T) {
		t.Run("Returns empty when no operations stored", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			opRouter := setupOperationsRouter(t, s)

			request := router.GetOperationsRequest{}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})

		t.Run("Returns one operation for every submission", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			submissionOp := createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			holderSigner2, holderDID2 := getSigner(t)
			submissionOp2 := createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID2, holderSigner2)

			request := router.GetOperationsRequest{}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
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
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Filter: "done = false",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Len(t, resp.Operations, 1)
			assert.False(t, resp.Operations[0].Done)
		})

		t.Run("Returns zero operations when filtering to exclude", func(t *testing.T) {
			s, err := storage.NewBoltDB()
			assert.NoError(t, err)
			pRouter := setupPresentationRouter(t, s)
			opRouter := setupOperationsRouter(t, s)

			def := createPresentationDefinition(t, pRouter)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Filter: "done = true",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			assert.NoError(t, opRouter.GetOperations(newRequestContext(), w, req))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})
	})

}

func setupOperationsRouter(t *testing.T, s storage.ServiceStorage) *router.OperationRouter {
	t.Cleanup(func() {
		assert.NoError(t, s.Close())
		assert.NoError(t, os.Remove(storage.DBFile))
	})
	svc, err := operation.NewOperationService(s)
	assert.NoError(t, err)
	opRouter, err := router.NewOperationRouter(svc)
	assert.NoError(t, err)
	return opRouter
}
