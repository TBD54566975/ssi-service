package middleware

import (
	"bytes"
	"context"
	"net/http"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

// Define a custom response writer that wraps the original response writer and writes to a buffer
type responseWriter struct {
	http.ResponseWriter
	buf *bytes.Buffer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Write the response body to both the original response writer and the buffer
	n, err := rw.ResponseWriter.Write(b)
	if err != nil {
		return n, err
	}

	if _, err = rw.buf.Write(b); err != nil {
		return n, err
	}

	return n, err
}

func Webhook(webhookService svcframework.Service, noun webhook.Noun, verb webhook.Verb) framework.Middleware {
	return func(handler framework.Handler) framework.Handler {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			buf := bytes.NewBuffer([]byte{})

			// Wrap the original response writer with a new response writer that writes to the buffer
			wrappedWriter := &responseWriter{w, buf}

			// Call the original handler with the new response writer
			err := handler(ctx, wrappedWriter, r)

			whService := webhookService.(*webhook.Service)
			go whService.PublishWebhook(noun, verb, buf)

			return err
		}
	}
}
