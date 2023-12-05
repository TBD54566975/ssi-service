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
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func freePort() string {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Failed to listen:", err)
		return ""
	}
	defer func(listener net.Listener) {
		_ = listener.Close()
	}(listener)
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

func TestSimpleWebhook(t *testing.T) {
	ch := make(chan []byte, 10)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		ch <- received
	}))
	defer testServer.Close()

	shutdown := make(chan os.Signal, 1)
	serviceConfig, err := config.LoadConfig("", nil)
	assert.NoError(t, err)

	serviceConfig.Server.APIHost = "0.0.0.0:" + freePort()
	name := tempBoltFileName(t)
	serviceConfig.Services.StorageOptions = append(serviceConfig.Services.StorageOptions, storage.Option{
		ID:     "boltdb-filepath-option",
		Option: name,
	})

	server, err := NewSSIServer(shutdown, *serviceConfig)
	assert.NoError(t, err)

	go func() {
		require.ErrorIs(t, server.ListenAndServe(), http.ErrServerClosed)
	}()

	require.Eventually(t, isHealthy(t, server), 30*time.Second, 100*time.Millisecond)

	webhookRequest := router.CreateWebhookRequest{
		Noun: "DID",
		Verb: "Create",
		URL:  testServer.URL,
	}
	requestData, err := json.Marshal(webhookRequest)
	assert.NoError(t, err)

	put(t, server, "/v1/webhooks", requestData)

	createRequest := []byte(`{
		"keyType":"Ed25519"
	}`)
	put(t, server, "/v1/dids/key", createRequest)

	// Check that exactly one call was received after 2 seconds.
	select {
	case received := <-ch:
		var parsed map[string]any
		assert.NoError(t, json.Unmarshal(received, &parsed))
		assert.NotEmpty(t, parsed["data"])

		dataJSON, err := json.Marshal(parsed["data"])
		assert.NoError(t, err)
		var resp router.CreateDIDByMethodResponse
		assert.NoError(t, json.Unmarshal(dataJSON, &resp))

		assert.True(t, strings.HasPrefix(resp.DID.ID, "did:key:"))
	case <-time.After(2 * time.Second):
		assert.Fail(t, "should receive at least 1 message")
	}
	select {
	case <-ch:
		assert.Fail(t, "should not receive more than 1 message")
	case <-time.After(2 * time.Second):
	}

	assert.NoError(t, server.Close())
}

func tempBoltFileName(t *testing.T) string {
	file, err := os.CreateTemp("", "bolt")
	require.NoError(t, err)
	name := file.Name()
	t.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove(name)
	})
	return name
}

func isHealthy(t *testing.T, server *SSIServer) func() bool {
	return func() bool {
		resp, err := http.Get("http://" + server.Addr + "/health")
		require.NoError(t, err)
		return resp.StatusCode == 200
	}
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
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("CreateWebhook returns error when missing request", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookRouter := testWebhookRouter(t, db)

				badWebhookRequest := router.CreateWebhookRequest{
					Noun: "Credential",
				}

				badRequestValue := newRequestValue(t, badWebhookRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				webhookRouter.CreateWebhook(c)
				assert.Contains(t, w.Body.String(), "invalid create webhook request")
			})

			t.Run("CreateWebhook returns error when verb is not supported", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookRouter := testWebhookRouter(t, db)

				badWebhookRequest := router.CreateWebhookRequest{
					Noun: "Credential",
					Verb: "bad",
					URL:  "www.abc.com",
				}

				badRequestValue := newRequestValue(t, badWebhookRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				webhookRouter.CreateWebhook(c)
				assert.Contains(t, w.Body.String(), "invalid create webhook request")
			})

			t.Run("CreateWebhook returns error when url is not supported", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookRouter := testWebhookRouter(t, db)

				badWebhookRequest := router.CreateWebhookRequest{
					Noun: "Credential",
					Verb: "Create",
					URL:  "badurl",
				}

				badRequestValue := newRequestValue(t, badWebhookRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				webhookRouter.CreateWebhook(c)
				assert.Contains(t, w.Body.String(), "invalid create webhook request")
			})

			t.Run("CreateWebhook returns error when url is is missing scheme", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookRouter := testWebhookRouter(t, db)

				badWebhookRequest := router.CreateWebhookRequest{
					Noun: "Credential",
					Verb: "Create",
					URL:  "www.tbd.website",
				}

				badRequestValue := newRequestValue(t, badWebhookRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				webhookRouter.CreateWebhook(c)
				assert.Contains(t, w.Body.String(), "invalid create webhook request")
			})

			t.Run("CreateWebhook returns valid response", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookRouter := testWebhookRouter(t, db)

				webhookRequest := router.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.website/",
				}

				requestValue := newRequestValue(t, webhookRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", requestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				webhookRouter.CreateWebhook(c)
				assert.True(t, util.Is2xxResponse(w.Code))
			})

			t.Run("Test Happy Path Delete Webhook", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookRouter := testWebhookRouter(t, db)

				webhookRequest := router.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.website/",
				}

				requestValue := newRequestValue(t, webhookRequest)
				req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", requestValue)
				w := httptest.NewRecorder()

				c := newRequestContext(w, req)
				webhookRouter.CreateWebhook(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
				w = httptest.NewRecorder()

				c = newRequestContext(w, req)
				webhookRouter.ListWebhooks(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var resp router.ListWebhooksResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				assert.NoError(t, err)
				assert.Len(t, resp.Webhooks, 1)

				c = newRequestContext(w, req)
				webhookRouter.ListWebhooks(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				deleteWebhookRequest := router.DeleteWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.website/",
				}

				requestValue = newRequestValue(t, deleteWebhookRequest)
				req = httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/webhooks", requestValue)
				w = httptest.NewRecorder()

				c = newRequestContext(w, req)
				webhookRouter.DeleteWebhook(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
				w = httptest.NewRecorder()

				c = newRequestContext(w, req)
				webhookRouter.ListWebhooks(c)
				assert.True(t, util.Is2xxResponse(w.Code))

				var respAfter router.ListWebhooksResponse
				err = json.NewDecoder(w.Body).Decode(&respAfter)
				assert.NoError(t, err)
				assert.Len(t, respAfter.Webhooks, 0)
			})

			t.Run("GetWebhook Throws Error When Webhook None Exist", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookService := testWebhookService(t, db)

				wh, err := webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Credential", Verb: "Create"})
				assert.ErrorContains(t, err, "webhook does not exist")
				assert.Nil(t, wh)
			})

			t.Run("GetWebhook Returns Webhook That Does Exist", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookService := testWebhookService(t, db)

				webhookRequest := webhook.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.website/",
				}

				createdWebhook, err := webhookService.CreateWebhook(context.Background(), webhookRequest)
				assert.NoError(t, err)
				assert.Equal(t, createdWebhook.Webhook.Noun, webhookRequest.Noun)
				assert.Equal(t, createdWebhook.Webhook.Verb, webhookRequest.Verb)
				assert.Equal(t, createdWebhook.Webhook.URLS[0], webhookRequest.URL)

				getWebhookRequest := webhook.GetWebhookRequest{Noun: "Manifest", Verb: "Create"}

				gotWebhook, err := webhookService.GetWebhook(context.Background(), getWebhookRequest)
				assert.NoError(t, err)
				assert.Equal(t, gotWebhook.Webhook.Noun, webhookRequest.Noun)
				assert.Equal(t, gotWebhook.Webhook.Verb, webhookRequest.Verb)
				assert.Equal(t, gotWebhook.Webhook.URLS[0], webhookRequest.URL)
			})

			t.Run("Test Get Webhooks", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookService := testWebhookService(t, db)

				gotWebhooks, err := webhookService.ListWebhooks(context.Background())
				assert.NoError(t, err)
				assert.Len(t, gotWebhooks.Webhooks, 0)

				_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.website/",
				})
				assert.NoError(t, err)

				_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.dev/",
				})
				assert.NoError(t, err)

				_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Delete",
					URL:  "https://www.tbd.website/",
				})
				assert.NoError(t, err)

				gotWebhooks, err = webhookService.ListWebhooks(context.Background())
				assert.NoError(t, err)
				assert.Len(t, gotWebhooks.Webhooks, 2)
			})

			t.Run("Test Delete Webhook", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				webhookService := testWebhookService(t, db)

				err := webhookService.DeleteWebhook(context.Background(), webhook.DeleteWebhookRequest{Noun: "Credential", Verb: "Create", URL: "https://www.tbd.website/"})
				assert.ErrorContains(t, err, "webhook does not exist")

				_, err = webhookService.CreateWebhook(context.Background(), webhook.CreateWebhookRequest{
					Noun: "Manifest",
					Verb: "Create",
					URL:  "https://www.tbd.website/",
				})
				assert.NoError(t, err)

				gotWebhook, err := webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Manifest", Verb: "Create"})
				assert.NoError(t, err)
				assert.Equal(t, gotWebhook.Webhook.Noun, webhook.Noun("Manifest"))
				assert.Equal(t, gotWebhook.Webhook.Verb, webhook.Verb("Create"))
				assert.Equal(t, gotWebhook.Webhook.URLS[0], "https://www.tbd.website/")

				err = webhookService.DeleteWebhook(context.Background(), webhook.DeleteWebhookRequest{Noun: "Manifest", Verb: "Create", URL: "https://www.tbd.website/"})
				assert.NoError(t, err)

				gotWebhook, err = webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Manifest", Verb: "Create"})
				assert.ErrorContains(t, err, "webhook does not exist")
				assert.Empty(t, gotWebhook)
			})
		})
	}
}
