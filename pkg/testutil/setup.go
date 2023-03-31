package testutil

import (
	"context"
	"os"
	"time"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/google/uuid"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
)

func EnableSchemaCaching() {
	s, err := schema.GetAllLocalSchemas()
	if err != nil {
		println(err)
		os.Exit(1)
	}
	l, err := schema.NewCachingLoader(s)
	if err != nil {
		println(err)
		os.Exit(1)
	}
	l.EnableHTTPCache()
}

// NewRequestContext construct a context value as expected by our handlers
func NewRequestContext() context.Context {
	return context.WithValue(context.Background(), framework.KeyRequestState, &framework.RequestState{
		TraceID:    uuid.New().String(),
		Now:        time.Now(),
		StatusCode: 1,
	})
}
