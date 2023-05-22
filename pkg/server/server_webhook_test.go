package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/config"

	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

func freePort() string {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Failed to listen:", err)
		return ""
	}
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}
func TestSimpleWebhook(t *testing.T) {
	var received int64
	receivedOne := func() bool {
		return received == 1
	}
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&received, 1)
	}))
	defer testServer.Close()

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("")
	assert.NoError(t, err)
	serviceConfig.Server.APIHost = "0.0.0.0:" + freePort()
	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)
	assert.NotEmpty(t, server)

	go func() {
		require.ErrorIs(t, server.ListenAndServe(), http.ErrServerClosed)
	}()

	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + server.Addr + "/health")
		require.NoError(t, err)
		return resp.StatusCode == 200
	}, 30*time.Second, 100*time.Millisecond)

	webhookRequest := router.CreateWebhookRequest{
		Noun: "DID",
		Verb: "Create",
		URL:  testServer.URL,
	}
	requestData, err := json.Marshal(webhookRequest)
	assert.NoError(t, err)

	put(t, server, "/v1/webhooks", requestData)

	createRequest := []byte(`{
		"keyType":"Ed25519",
		"options": {
			"didWebId": "did:web:tbd.website"
		}
	}`)
	put(t, server, "/v1/dids/web", createRequest)

	<-time.After(500 * time.Millisecond)
	assert.Eventually(t, receivedOne, 5*time.Second, 10*time.Millisecond)

	assert.NoError(t, server.Close())
}

func put(t *testing.T, server *SSIServer, endpoint string, data []byte) {
	request, err := http.NewRequest(http.MethodPut, "http://"+server.Addr+endpoint, bytes.NewReader(data))
	assert.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, 2, res.StatusCode/100)
	body, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	assert.NotEmpty(t, string(body))
}

func TestWebhookAPI(t *testing.T) {
	t.Run("CreateWebhook returns error when missing request", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

		webhookRouter := testWebhookRouter(tt, db)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := webhookRouter.CreateWebhook(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("CreateWebhook returns error when verb is not supported", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

		webhookRouter := testWebhookRouter(tt, db)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
			Verb: "bad",
			URL:  "www.abc.com",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := webhookRouter.CreateWebhook(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("CreateWebhook returns error when url is not supported", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

		webhookRouter := testWebhookRouter(tt, db)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
			Verb: "Create",
			URL:  "badurl",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := webhookRouter.CreateWebhook(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("CreateWebhook returns error when url is is missing scheme", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookRouter := testWebhookRouter(tt, db)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
			Verb: "Create",
			URL:  "www.tbd.website",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := webhookRouter.CreateWebhook(c)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("CreateWebhook returns valid response", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookRouter := testWebhookRouter(tt, db)

		webhookRequest := router.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue := newRequestValue(tt, webhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", requestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := webhookRouter.CreateWebhook(c)
		assert.NoError(tt, err)
	})

	t.Run("Test Happy Path Delete Webhook", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookRouter := testWebhookRouter(tt, db)

		webhookRequest := router.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue := newRequestValue(tt, webhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", requestValue)
		w := httptest.NewRecorder()

		c := newRequestContext(w, req)
		err := webhookRouter.CreateWebhook(c)
		assert.NoError(tt, err)

		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
		w = httptest.NewRecorder()

		c = newRequestContext(w, req)
		err = webhookRouter.GetWebhooks(c)
		assert.NoError(tt, err)

		var resp router.GetWebhooksResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Len(tt, resp.Webhooks, 1)

		c = newRequestContext(w, req)
		err = webhookRouter.GetWebhooks(c)
		assert.NoError(tt, err)

		deleteWebhookRequest := router.DeleteWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue = newRequestValue(tt, deleteWebhookRequest)
		req = httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/webhooks", requestValue)
		w = httptest.NewRecorder()

		c = newRequestContext(w, req)
		err = webhookRouter.DeleteWebhook(c)
		assert.NoError(tt, err)

		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
		w = httptest.NewRecorder()

		c = newRequestContext(w, req)
		err = webhookRouter.GetWebhooks(c)
		assert.NoError(tt, err)

		var respAfter router.GetWebhooksResponse
		err = json.NewDecoder(w.Body).Decode(&respAfter)
		assert.NoError(tt, err)
		assert.Len(tt, respAfter.Webhooks, 0)
	})

	t.Run("GetWebhook Throws Error When Webhook None Exist", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookService := testWebhookService(tt, db)

		webhook, err := webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Credential", Verb: "Create"})
		assert.ErrorContains(tt, err, "webhook does not exist")
		assert.Nil(tt, webhook)
	})

	t.Run("GetWebhook Returns Webhook That Does Exist", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookService := testWebhookService(tt, db)

		webhookRequest := webhook.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		createdWebhook, err := webhookService.CreateWebhook(context.Background(), webhookRequest)
		assert.NoError(tt, err)
		assert.Equal(tt, createdWebhook.Webhook.Noun, webhookRequest.Noun)
		assert.Equal(tt, createdWebhook.Webhook.Verb, webhookRequest.Verb)
		assert.Equal(tt, createdWebhook.Webhook.URLS[0], webhookRequest.URL)

		getWebhookRequest := webhook.GetWebhookRequest{Noun: "Manifest", Verb: "Create"}

		gotWebhook, err := webhookService.GetWebhook(context.Background(), getWebhookRequest)
		assert.NoError(tt, err)
		assert.Equal(tt, gotWebhook.Webhook.Noun, webhookRequest.Noun)
		assert.Equal(tt, gotWebhook.Webhook.Verb, webhookRequest.Verb)
		assert.Equal(tt, gotWebhook.Webhook.URLS[0], webhookRequest.URL)
	})

	t.Run("Test Get Webhooks", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookService := testWebhookService(tt, db)

		gotWebhooks, err := webhookService.GetWebhooks(context.Background())
		assert.NoError(tt, err)
		assert.Len(tt, gotWebhooks.Webhooks, 0)

		_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		})
		assert.NoError(tt, err)

		_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.dev/",
		})
		assert.NoError(tt, err)

		_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Delete",
			URL:  "https://www.tbd.website/",
		})
		assert.NoError(tt, err)

		gotWebhooks, err = webhookService.GetWebhooks(context.Background())
		assert.NoError(tt, err)
		assert.Len(tt, gotWebhooks.Webhooks, 2)
	})

	t.Run("Test Delete Webhook", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotNil(tt, db)

		webhookService := testWebhookService(tt, db)

		err := webhookService.DeleteWebhook(context.Background(), webhook.DeleteWebhookRequest{Noun: "Credential", Verb: "Create", URL: "https://www.tbd.website/"})
		assert.ErrorContains(tt, err, "webhook does not exist")

		_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		})
		assert.NoError(tt, err)

		gotWebhook, err := webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Manifest", Verb: "Create"})
		assert.NoError(tt, err)
		assert.Equal(tt, gotWebhook.Webhook.Noun, webhook.Noun("Manifest"))
		assert.Equal(tt, gotWebhook.Webhook.Verb, webhook.Verb("Create"))
		assert.Equal(tt, gotWebhook.Webhook.URLS[0], "https://www.tbd.website/")

		err = webhookService.DeleteWebhook(context.Background(), webhook.DeleteWebhookRequest{Noun: "Manifest", Verb: "Create", URL: "https://www.tbd.website/"})
		assert.NoError(tt, err)

		gotWebhook, err = webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Manifest", Verb: "Create"})
		assert.ErrorContains(tt, err, "webhook does not exist")
		assert.Nil(tt, gotWebhook)
	})
}
