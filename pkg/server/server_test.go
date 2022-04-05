package server

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAPI(t *testing.T) {

	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	t.Run("Test Health Check", func(tt *testing.T) {
		shutdown := make(chan os.Signal, 1)
		logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)
		server, err := NewSSIServer(shutdown, service.Config{Logger: logger})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, server)

		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/health", nil)
		w := httptest.NewRecorder()

		err = router.Health(context.TODO(), w, req)
		assert.NoError(tt, err)
		assert.Equal(tt, http.StatusOK, w.Result().StatusCode)

		var resp router.GetHealthCheckResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Equal(tt, router.HealthOK, resp.Status)
	})

	t.Run("Test Readiness Check", func(tt *testing.T) {
		shutdown := make(chan os.Signal, 1)
		logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)
		server, err := NewSSIServer(shutdown, service.Config{Logger: logger})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, server)

		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/readiness", nil)
		w := httptest.NewRecorder()

		handler := router.Readiness(nil, logger)
		err = handler(newRequestContext(), w, req)
		assert.NoError(tt, err)
		assert.Equal(tt, http.StatusOK, w.Result().StatusCode)

		var resp router.GetReadinessResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Equal(tt, svcframework.StatusReady, resp.Status.Status)
		assert.Len(tt, resp.ServiceStatuses, 0)
	})
}

func newRequestContext() context.Context {
	return context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
}

func TestDIDAPI(t *testing.T) {

}
