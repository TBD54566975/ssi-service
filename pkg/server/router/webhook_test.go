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
	t.Run("Nil Service", func(tt *testing.T) {
		webhookRouter, err := NewWebhookRouter(nil)
		assert.Error(tt, err)
		assert.Empty(tt, webhookRouter)
		assert.Contains(tt, err.Error(), "service cannot be nil")
	})

	t.Run("Bad Service", func(tt *testing.T) {
		webhookRouter, err := NewWebhookRouter(&testService{})
		assert.Error(tt, err)
		assert.Empty(tt, webhookRouter)
		assert.Contains(tt, err.Error(), "could not create webhook router with service type: test")
	})

	for _, test := range testutil.TestDatabases {
		t.Run(test.Name, func(t *testing.T) {
			t.Run("Webhook Service Test", func(tt *testing.T) {
				db := test.ServiceStorage(tt)
				require.NotEmpty(tt, db)

				serviceConfig := config.WebhookServiceConfig{WebhookTimeout: "10s"}
				webhookService, err := webhook.NewWebhookService(serviceConfig, db)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, webhookService)

				// check type and status
				assert.Equal(tt, framework.Webhook, webhookService.Type())
				assert.Equal(tt, framework.StatusReady, webhookService.Status().Status)
			})
		})
	}
}
