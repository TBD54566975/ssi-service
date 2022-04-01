package server

import (
	"context"
	"encoding/json"
	"net/http"
)

// health is a simple handler that always responds with a 200 OK
func health(_ context.Context, w http.ResponseWriter, _ *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "OK",
	}
	return json.NewEncoder(w).Encode(status)
}
