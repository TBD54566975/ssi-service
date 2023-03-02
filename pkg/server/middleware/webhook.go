package middleware

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

const (
	V1Prefix          = "/v1"
	DIDsPrefix        = "/dids"
	CredentialsPrefix = "/credentials"
)

// Define a custom response writer that wraps the original response writer and writes to a buffer
type responseWriter struct {
	http.ResponseWriter
	buf *bytes.Buffer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Write the response body to both the original response writer and the buffer
	n, err := rw.ResponseWriter.Write(b)
	if err == nil {
		rw.buf.Write(b)
	}
	return n, err
}

func Webhook(webhookService svcframework.Service) framework.Middleware {
	return func(handler framework.Handler) framework.Handler {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			buf := bytes.NewBuffer([]byte{})

			// Wrap the original response writer with a new response writer that writes to the buffer
			wrappedWriter := &responseWriter{w, buf}

			// Call the original handler with the new response writer
			err := handler(ctx, wrappedWriter, r)
			body := buf.String()

			didHandlerPath := V1Prefix + DIDsPrefix
			credHandlerPath := V1Prefix + CredentialsPrefix

			whService := webhookService.(*webhook.Service)

			switch r.Method {
			case http.MethodPut:
				if strings.Contains(r.URL.Path, didHandlerPath) {
					go whService.PublishWebhook(webhook.DID, webhook.Create, body)
				} else if strings.Contains(r.URL.Path, credHandlerPath) {
					go whService.PublishWebhook(webhook.Credential, webhook.Create, body)
				}
			case http.MethodDelete:
				if strings.Contains(r.URL.Path, credHandlerPath) {
					go whService.PublishWebhook(webhook.Credential, webhook.Delete, body)
				}
			}
			return err
		}
	}
}
