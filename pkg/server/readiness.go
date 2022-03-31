package server

import (
	"context"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"log"
	"net/http"
)

type Readiness struct {
	Log *log.Logger
}

// Readiness handler runs a number of application specific checks to see if all the
// relied upon services are healthy. Should return a 500 if not ready.
func (_ Readiness) handle(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	// TODO: add application specific checks (e.g. have we established a connection to the DB?)
	status := struct {
		Status string
	}{
		Status: "OK",
	}

	return framework.Respond(ctx, w, status, http.StatusOK)
}
