package handlers

import (
	"context"
	"log"
	"net/http"

	"github.com/tbd54566975/vc-service/framework"
)

type readiness struct {
	log *log.Logger
}

// readiness handler runs a number of application specific checks to see if all of the
// relied upon services are healthy. Should return a 500 if not ready.
func (_ readiness) handle(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	// TODO: add application specific checks (e.g. have we established a connection to the DB?)
	status := struct {
		Status string
	}{
		Status: "OK",
	}

	return framework.Respond(ctx, w, status, http.StatusOK)
}
