package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestHealthCheckAPI(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	shutdown := make(chan os.Signal, 1)
	logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)
	server, err := NewSSIServer(shutdown, service.Config{Logger: logger})
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/health", nil)
	w := httptest.NewRecorder()

	err = router.Health(context.TODO(), w, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var resp router.GetHealthCheckResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.Equal(t, router.HealthOK, resp.Status)

}

func TestReadinessAPI(t *testing.T) {
	// remove the db file after the test
	t.Cleanup(func() {
		_ = os.Remove(storage.DBFile)
	})

	shutdown := make(chan os.Signal, 1)
	logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)
	server, err := NewSSIServer(shutdown, service.Config{Logger: logger})
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/readiness", nil)
	w := httptest.NewRecorder()

	handler := router.Readiness(nil, logger)
	err = handler(newRequestContext(), w, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	var resp router.GetReadinessResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)

	assert.Equal(t, svcframework.StatusReady, resp.Status.Status)
	assert.Len(t, resp.ServiceStatuses, 0)
}

func TestDIDAPI(t *testing.T) {
	t.Run("Test Get Author Methods", func(tt *testing.T) {
		// remove the db file after the test
		tt.Cleanup(func() {
			_ = os.Remove(storage.DBFile)
		})

		didRouter := newDIDService(tt)

		// get Author methods
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids", nil)
		w := httptest.NewRecorder()

		err := didRouter.GetDIDMethods(newRequestContext(), w, req)
		assert.NoError(tt, err)
		assert.Equal(tt, http.StatusOK, w.Result().StatusCode)

		var resp router.GetDIDMethodsResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Len(tt, resp.DIDMethods, 1)
		assert.Equal(tt, resp.DIDMethods[0], did.KeyMethod)
	})

	t.Run("Test Create Author By Method: Key", func(tt *testing.T) {
		// remove the db file after the test
		tt.Cleanup(func() {
			_ = os.Remove(storage.DBFile)
		})

		didRouter := newDIDService(tt)

		// create Author by method - key - missing body
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", nil)
		w := httptest.NewRecorder()
		params := map[string]string{
			"method": "key",
		}

		err := didRouter.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create Author request")

		// with body, bad key type
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: "bad"}
		requestReader := newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
		w = httptest.NewRecorder()

		err = didRouter.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not create Author for method<key> with key type: bad")

		// with body, good key type
		createDIDRequest = router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader = newRequestValue(tt, createDIDRequest)
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
		w = httptest.NewRecorder()

		err = didRouter.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var resp router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)

		assert.Contains(tt, resp.DID.ID, did.KeyMethod)
	})

	t.Run("Test Get Author By Method", func(tt *testing.T) {
		// remove the db file after the test
		tt.Cleanup(func() {
			_ = os.Remove(storage.DBFile)
		})

		didRouter := newDIDService(tt)

		// get Author by method
		req := httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/dids/bad/worse", nil)
		w := httptest.NewRecorder()

		// bad params
		badParams := map[string]string{
			"method": "bad",
			"id":     "worse",
		}
		err := didRouter.GetDIDByMethod(newRequestContextWithParams(badParams), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get Author for method<bad>")

		// good method, bad id
		badParams1 := map[string]string{
			"method": "key",
			"id":     "worse",
		}
		err = didRouter.GetDIDByMethod(newRequestContextWithParams(badParams1), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not get Author for method<key> with id: worse")

		// store a Author
		createDIDRequest := router.CreateDIDByMethodRequest{KeyType: crypto.Ed25519}
		requestReader := newRequestValue(tt, createDIDRequest)
		params := map[string]string{"method": "key"}
		req = httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/dids/key", requestReader)
		w = httptest.NewRecorder()

		err = didRouter.CreateDIDByMethod(newRequestContextWithParams(params), w, req)
		assert.NoError(tt, err)

		var createdDID router.CreateDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&createdDID)
		assert.NoError(tt, err)

		// get it back
		createdID := createdDID.DID.ID
		getDIDPath := fmt.Sprintf("https://ssi-service.com/v1/dids/key/%s", createdID)
		req = httptest.NewRequest(http.MethodGet, getDIDPath, nil)
		w = httptest.NewRecorder()

		// good params
		goodParams := map[string]string{
			"method": "key",
			"id":     createdID,
		}
		err = didRouter.GetDIDByMethod(newRequestContextWithParams(goodParams), w, req)
		assert.NoError(tt, err)

		var resp router.GetDIDByMethodResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Equal(tt, createdID, resp.DID.ID)
	})
}

func newDIDService(t *testing.T) *router.DIDRouter {
	// set up Author service
	bolt, err := storage.NewBoltDB()
	require.NoError(t, err)
	require.NotEmpty(t, bolt)

	logger := log.New(os.Stdout, "ssi-test", log.LstdFlags)
	didService, err := did.NewDIDService(logger, []did.Method{did.KeyMethod}, bolt)
	require.NoError(t, err)
	require.NotEmpty(t, didService)

	// create router for service
	didRouter, err := router.NewDIDRouter(didService, logger)
	require.NoError(t, err)
	require.NotEmpty(t, didRouter)

	return didRouter
}

func newRequestValue(t *testing.T, data interface{}) io.Reader {
	dataBytes, err := json.Marshal(data)
	require.NoError(t, err)
	require.NotEmpty(t, dataBytes)
	return bytes.NewReader(dataBytes)
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
