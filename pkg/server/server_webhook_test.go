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
		webhookRouter.CreateWebhook(c)
		assert.Contains(tt, w.Body.String(), "invalid create webhook request")
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
		webhookRouter.CreateWebhook(c)
		assert.Contains(tt, w.Body.String(), "invalid create webhook request")
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
		webhookRouter.CreateWebhook(c)
		assert.Contains(tt, w.Body.String(), "invalid create webhook request")
	})

	t.Run("CreateWebhook returns error when url is is missing scheme", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

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
		webhookRouter.CreateWebhook(c)
		assert.Contains(tt, w.Body.String(), "invalid create webhook request")
	})

	t.Run("CreateWebhook returns valid response", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

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
		webhookRouter.CreateWebhook(c)
		assert.True(tt, is2xxResponse(w.Code))
	})

	t.Run("Test Happy Path Delete Webhook", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

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
		webhookRouter.CreateWebhook(c)
		assert.True(tt, is2xxResponse(w.Code))

		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
		w = httptest.NewRecorder()

		c = newRequestContext(w, req)
		webhookRouter.GetWebhooks(c)
		assert.True(tt, is2xxResponse(w.Code))

		var resp router.GetWebhooksResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		assert.NoError(tt, err)
		assert.Len(tt, resp.Webhooks, 1)

		c = newRequestContext(w, req)
		webhookRouter.GetWebhooks(c)
		assert.True(tt, is2xxResponse(w.Code))

		deleteWebhookRequest := router.DeleteWebhookRequest{
			Noun: "Manifest",
			Verb: "Create",
			URL:  "https://www.tbd.website/",
		}

		requestValue = newRequestValue(tt, deleteWebhookRequest)
		req = httptest.NewRequest(http.MethodDelete, "https://ssi-service.com/v1/webhooks", requestValue)
		w = httptest.NewRecorder()

		c = newRequestContext(w, req)
		webhookRouter.DeleteWebhook(c)
		assert.True(tt, is2xxResponse(w.Code))

		req = httptest.NewRequest(http.MethodGet, "https://ssi-service.com/v1/webhooks", nil)
		w = httptest.NewRecorder()

		c = newRequestContext(w, req)
		webhookRouter.GetWebhooks(c)
		assert.True(tt, is2xxResponse(w.Code))

		var respAfter router.GetWebhooksResponse
		err = json.NewDecoder(w.Body).Decode(&respAfter)
		assert.NoError(tt, err)
		assert.Len(tt, respAfter.Webhooks, 0)
	})

	t.Run("GetWebhook Throws Error When Webhook None Exist", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

		webhookService := testWebhookService(tt, db)

		wh, err := webhookService.GetWebhook(context.Background(), webhook.GetWebhookRequest{Noun: "Credential", Verb: "Create"})
		assert.ErrorContains(tt, err, "wh does not exist")
		assert.Nil(tt, wh)
	})

	t.Run("GetWebhook Returns Webhook That Does Exist", func(tt *testing.T) {
		db := setupTestDB(tt)
		require.NotEmpty(tt, db)

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
		require.NotEmpty(tt, db)

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
		require.NotEmpty(tt, db)

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
		assert.Empty(tt, gotWebhook)
	})
}
