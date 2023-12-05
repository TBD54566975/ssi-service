package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tbd54566975/ssi-service/config"
	"github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
	"github.com/tbd54566975/ssi-service/pkg/testutil"
)

func TestWebhookRouter(t *testing.T) {
	t.Run("Nil Service", func(t *testing.T) {
		webhookRouter, err := NewWebhookRouter(nil)
		assert.Error(t, err)
		assert.Empty(t, webhookRouter)
		assert.Contains(t, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(t *testing.T) {
		webhookRouter, err := NewWebhookRouter(&testService{})
		assert.Error(t, err)
		assert.Empty(t, webhookRouter)
		assert.Contains(t, err.Error(), "could not create webhook router with service type: test")
	})
}

func TestWebhookService(t *testing.T) {
	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Webhook Service Test", func(t *testing.T) {
				db := test.ServiceStorage(t)
				require.NotEmpty(t, db)

				serviceConfig := config.WebhookServiceConfig{WebhookTimeout: "10s"}
				webhookService, err := webhook.NewWebhookService(serviceConfig, db)
				assert.NoError(t, err)
				assert.NotEmpty(t, webhookService)

				// check type and status
				assert.Equal(t, framework.Webhook, webhookService.Type())
				assert.Equal(t, framework.StatusReady, webhookService.Status().Status)
			})
		})
	}
}
