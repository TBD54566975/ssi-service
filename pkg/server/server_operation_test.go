package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/goccy/go-json"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	opstorage "github.com/tbd54566975/ssi-service/pkg/service/operation/storage"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

func TestOperationsAPI(t *testing.T) {
	t.Run("Marks operation as done after reviewing submission", func(tt *testing.T) {
		s := setupTestDB(tt)
		pRouter, didService := setupPresentationRouter(t, s)
		authorDID := createDID(t, didService)
		opRouter := setupOperationsRouter(t, s)

		holderSigner, holderDID := getSigner(t)
		kid := authorDID.DID.VerificationMethod[0].ID
		definition := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
		submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
		sub := reviewSubmission(t, pRouter, opstorage.StatusObjectID(submissionOp.ID))

		createdID := submissionOp.ID
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID), nil)
		w := httptest.NewRecorder()

		c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
		err := opRouter.GetOperation(c)

		assert.NoError(t, err)
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
		t.Run("Returns operation after submission", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			kid := authorDID.DID.VerificationMethod[0].ID
			definition := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

			createdID := submissionOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()

			c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
			err := opRouter.GetOperation(c)
			assert.NoError(t, err)

			var resp router.Operation
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.False(t, resp.Done)
			assert.Contains(t, resp.ID, "presentations/submissions/")
		})

		t.Run("Returns error when id doesn't exist", func(tt *testing.T) {
			s := setupTestDB(tt)
			opRouter := setupOperationsRouter(t, s)

			req := httptest.NewRequest(
				http.MethodPut,
				"https://ssi-service.com/v1/operations/some_fake_id",
				nil)
			w := httptest.NewRecorder()

			c := newRequestContextWithParams(w, req, map[string]string{"id": "some_fake_id"})
			err := opRouter.GetOperation(c)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "operation not found with id")
		})
	})

	t.Run("GetOperations", func(t *testing.T) {
		t.Run("Returns empty when no operations stored", func(tt *testing.T) {
			s := setupTestDB(tt)
			opRouter := setupOperationsRouter(t, s)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			c := newRequestContext(w, req)
			assert.NoError(t, opRouter.GetOperations(c))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})

		t.Run("Returns one operation for every submission", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			kid := authorDID.DID.VerificationMethod[0].ID
			def := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			holderSigner, holderDID := getSigner(t)
			submissionOp := createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

			holderSigner2, holderDID2 := getSigner(t)
			submissionOp2 := createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID2, holderSigner2)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			c := newRequestContext(w, req)
			assert.NoError(t, opRouter.GetOperations(c))

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

		t.Run("Returns operation when filtering to include", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			kid := authorDID.DID.VerificationMethod[0].ID
			def := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
				Filter: "done = false",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			c := newRequestContext(w, req)
			assert.NoError(t, opRouter.GetOperations(c))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Len(t, resp.Operations, 1)
			assert.False(t, resp.Operations[0].Done)
		})

		t.Run("Returns zero operations when filtering to exclude", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			kid := authorDID.DID.VerificationMethod[0].ID
			def := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Parent: "presentations/submissions",
				Filter: "done = true",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			c := newRequestContext(w, req)
			assert.NoError(t, opRouter.GetOperations(c))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})

		t.Run("Returns zero operations when wrong parent is specified", func(tt *testing.T) {
			s := setupTestDB(tt)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			kid := authorDID.DID.VerificationMethod[0].ID
			def := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			holderSigner, holderDID := getSigner(t)
			_ = createSubmission(t, pRouter, def.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

			request := router.GetOperationsRequest{
				Parent: "/presentations/other",
			}
			value := newRequestValue(t, request)
			req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/operations", value)
			w := httptest.NewRecorder()

			c := newRequestContext(w, req)
			assert.NoError(t, opRouter.GetOperations(c))

			var resp router.GetOperationsResponse
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.Empty(t, resp.Operations)
		})
	})

	t.Run("CancelOperation", func(t *testing.T) {
		t.Run("Marks an operation as done", func(t *testing.T) {
			s := setupTestDB(t)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			kid := authorDID.DID.VerificationMethod[0].ID
			definition := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)

			createdID := submissionOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()

			c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
			err := opRouter.CancelOperation(c)
			assert.NoError(t, err)

			var resp router.Operation
			assert.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
			assert.True(t, resp.Done)
			assert.Contains(t, resp.Result.Response, "verifiablePresentation")
			assert.Equal(t, "cancelled", resp.Result.Response.(map[string]any)["status"])
		})

		t.Run("Returns error when operation is done already", func(t *testing.T) {
			s := setupTestDB(t)
			pRouter, didService := setupPresentationRouter(t, s)
			authorDID := createDID(t, didService)
			opRouter := setupOperationsRouter(t, s)

			holderSigner, holderDID := getSigner(t)
			kid := authorDID.DID.VerificationMethod[0].ID
			definition := createPresentationDefinition(t, pRouter, authorDID.DID.ID, kid)
			submissionOp := createSubmission(t, pRouter, definition.PresentationDefinition.ID, authorDID.DID.ID, VerifiableCredential(), holderDID, holderSigner)
			_ = reviewSubmission(t, pRouter, opstorage.StatusObjectID(submissionOp.ID))

			createdID := submissionOp.ID
			req := httptest.NewRequest(
				http.MethodPut,
				fmt.Sprintf("https://ssi-service.com/v1/operations/%s", createdID),
				nil)
			w := httptest.NewRecorder()
			c := newRequestContextWithParams(w, req, map[string]string{"id": createdID})
			err := opRouter.CancelOperation(c)
			assert.Error(t, err)
		})
	})

}

func setupTestDB(t *testing.T) storage.ServiceStorage {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	s, err := storage.NewStorage(storage.Bolt, storage.Option{
		ID:     storage.BoltDBFilePathOption,
		Option: name,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Close()
		_ = file.Close()
		_ = os.Remove(name)
	})
	return s
}

func reviewSubmission(t *testing.T, pRouter *router.PresentationRouter, submissionID string) router.ReviewSubmissionResponse {
	request := router.ReviewSubmissionRequest{
		Approved: true,
		Reason:   "because I want to",
	}

	value := newRequestValue(t, request)
	req := httptest.NewRequest(
		http.MethodPut,
		fmt.Sprintf("https://ssi-service.com/v1/presentations/submissions/%s/review", submissionID),
		value)
	w := httptest.NewRecorder()
	c := newRequestContextWithParams(w, req, map[string]string{"id": submissionID})
	err := pRouter.ReviewSubmission(c)
	assert.NoError(t, err)

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
