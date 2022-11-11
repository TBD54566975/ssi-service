package router

import (
	"context"
	"fmt"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/submission"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSubmissionRouter_CreateSubmission(t *testing.T) {
	router := createRouter(t)

	t.Run("simple jwt return submission object", func(t *testing.T) {
		t.Cleanup(func() {
			_ = os.Remove(storage.DBFile)
		})

		jsonRequestString := `{"presentationJwt":"hello"}`
		r := httptest.NewRequest(http.MethodPut, "http://localhost/v1/presentations/submissions", strings.NewReader(jsonRequestString))
		w := httptest.NewRecorder()

		assert.NoError(t, router.CreateSubmission(newRequestContext(), w, r))

		readBody, err := io.ReadAll(w.Body)
		assert.NoError(t, err)
		assert.Equal(t, `{"status":"pending","submission":{"id":"dummy value","definition_id":"another dummy","descriptor_map":[{"id":"what?","format":"jwt_vp","path":"ohhh yeah"}]}}`, fmt.Sprintf("%s", readBody))
	})

	t.Run("missing jwt returns error", func(t *testing.T) {
		jsonRequestString := `{}`
		r := httptest.NewRequest(http.MethodPut, "http://localhost/v1/presentations/submissions", strings.NewReader(jsonRequestString))
		w := httptest.NewRecorder()

		assert.Error(t, router.CreateSubmission(newRequestContext(), w, r))
	})
}

func createRouter(t *testing.T) *SubmissionRouter {
	svcStorage, err := storage.NewStorage(storage.Bolt)
	assert.NoError(t, err)
	submissionService, err := submission.NewSubmissionService(config.SubmissionServiceConfig{}, svcStorage)
	assert.NoError(t, err)
	router, err := NewSubmissionRouter(submissionService)
	assert.NoError(t, err)
	return router
}

func TestSubmissionRouter_GetSubmission(t *testing.T) {
	router := createRouter(t)
	t.Run("get returns error when not found", func(t *testing.T) {
		jsonRequestString := `{"presentationJwt":"hello"}`
		r := httptest.NewRequest(http.MethodPut, "http://localhost/v1/presentations/submissions", strings.NewReader(jsonRequestString))
		w := httptest.NewRecorder()

		assert.Error(t, router.GetSubmission(newRequestContextWithParams(map[string]string{"id": "dummy value"}), w, r))
	})

	t.Run("returns resource after creating it", func(t *testing.T) {
		t.Cleanup(func() {
			_ = os.Remove(storage.DBFile)
		})
		jsonRequestString := `{"presentationJwt":"hello"}`
		r := httptest.NewRequest(http.MethodPut, "http://localhost/v1/presentations/submissions", strings.NewReader(jsonRequestString))
		w := httptest.NewRecorder()
		assert.NoError(t, router.CreateSubmission(newRequestContext(), w, r))

		r = httptest.NewRequest(http.MethodGet, "http://localhost/v1/presentations/submissions", strings.NewReader(""))
		w = httptest.NewRecorder()
		assert.NoError(t, router.GetSubmission(newRequestContextWithParams(map[string]string{"id": "dummy value"}), w, r))

		readBody, err := io.ReadAll(w.Body)
		assert.NoError(t, err)
		assert.Equal(t, `{"submission":{"id":"dummy value","definition_id":"another dummy","descriptor_map":[{"id":"what?","format":"jwt_vp","path":"ohhh yeah"}]}}`, fmt.Sprintf("%s", readBody))
	})
}

// construct a context value as expected by our handler
func newRequestContext() context.Context {
	return context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
}

// as required by https://github.com/dimfeld/httptreemux's context handler
func newRequestContextWithParams(params map[string]string) context.Context {
	ctx := context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
	return httptreemux.AddParamsToContext(ctx, params)
}
