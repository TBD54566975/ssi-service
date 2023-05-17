package middleware

import (
	"bytes"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/webhook"
)

// Define a custom response writer that wraps the original response writer and writes to a buffer
type responseWriter struct {
	gin.ResponseWriter
	buf *bytes.Buffer
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Write the response body to both the original response writer and the buffer
	if n, err := rw.buf.Write(b); err != nil {
		return n, err
	}
	return rw.ResponseWriter.Write(b)
}

func Webhook(webhookService svcframework.Service, noun webhook.Noun, verb webhook.Verb) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Wrap the original response writer with a new response writer that writes to the buffer
		buf := bytes.NewBuffer([]byte{})
		wrappedWriter := &responseWriter{ResponseWriter: c.Writer, buf: buf}
		c.Writer = wrappedWriter

		// run the middleware after the request handler
		c.Next()

		// make sure the response was already written
		if !c.Writer.Written() {
			_ = c.AbortWithError(http.StatusInternalServerError, errors.New("error sending webhook: response was not written"))
			return
		}

		// publish the webhook
		whService := webhookService.(*webhook.Service)
		go whService.PublishWebhook(noun, verb, buf)
	}
}
