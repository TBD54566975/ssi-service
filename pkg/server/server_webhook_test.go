package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tbd54566975/ssi-service/pkg/server/router"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

func TestWebhookAPI(t *testing.T) {
	t.Run("Test Missing Request Create Webhook", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookRouter := testWebhookRouter(tt, bolt)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		err := webhookRouter.CreateWebhook(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("Test Bad Request Create Webhook", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookRouter := testWebhookRouter(tt, bolt)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
			Verb: "bad",
			URL:  "www.abc.com",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		err := webhookRouter.CreateWebhook(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("Test Bad Request Create Webhook", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookRouter := testWebhookRouter(tt, bolt)

		badWebhookRequest := router.CreateWebhookRequest{
			Noun: "Credential",
			Verb: "Create",
			URL:  "badurl",
		}

		badRequestValue := newRequestValue(tt, badWebhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", badRequestValue)
		w := httptest.NewRecorder()

		err := webhookRouter.CreateWebhook(newRequestContext(), w, req)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "invalid create webhook request")
	})

	t.Run("Test Good Request Create Webhook", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookRouter := testWebhookRouter(tt, bolt)

		webhookRequest := router.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue := newRequestValue(tt, webhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", requestValue)
		w := httptest.NewRecorder()

		err := webhookRouter.CreateWebhook(newRequestContext(), w, req)
		assert.NoError(tt, err)
	})

	t.Run("Test Good Request Delete Webhook", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookRouter := testWebhookRouter(tt, bolt)

		webhookRequest := router.CreateWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue := newRequestValue(tt, webhookRequest)
		req := httptest.NewRequest(http.MethodPut, "https://ssi-service.com/v1/webhooks", requestValue)
		w := httptest.NewRecorder()

		err := webhookRouter.CreateWebhook(newRequestContext(), w, req)
		assert.NoError(tt, err)

		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
		w = httptest.NewRecorder()

		err = webhookRouter.GetWebhooks(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var resp router.GetWebhooksResponse
		err = json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Len(tt, resp.Webhooks, 1)

		err = webhookRouter.GetWebhooks(newRequestContext(), w, req)
		assert.NoError(tt, err)

		deleteWebhookRequest := router.DeleteWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue = newRequestValue(tt, deleteWebhookRequest)
		req = httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/webhooks", requestValue)
		w = httptest.NewRecorder()

		err = webhookRouter.DeleteWebhook(newRequestContext(), w, req)
		assert.NoError(tt, err)

		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
		w = httptest.NewRecorder()

		err = webhookRouter.GetWebhooks(newRequestContext(), w, req)
		assert.NoError(tt, err)

		var respAfter router.GetWebhooksResponse
		err = json.NewDecoder(w.Body).Decode(&respAfter)
		assert.NoError(tt, err)
		assert.Len(tt, respAfter.Webhooks, 0)
	})

	t.Run("Test Get Webhook None Exist", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookService := testWebhookService(tt, bolt)

		webhook, err := webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Credential", Verb: "Create"})
		assert.ErrorContains(tt, err, "webhook does not exist")
		assert.Nil(tt, webhook)
	})

	t.Run("Test Get Webhook Does Exist", func(tt *testing.T) {
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookService := testWebhookService(tt, bolt)

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
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookService := testWebhookService(tt, bolt)

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
		bolt := setupTestDB(tt)
		require.NotNil(tt, bolt)

		webhookService := testWebhookService(tt, bolt)

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
