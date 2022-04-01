package router

import (
	"context"
	"encoding/json"
	"net/http"
)

// Health is a simple handler that always responds with a 200 OK
func Health(_ context.Context, w http.ResponseWriter, _ *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "OK",
	}
	return json.NewEncoder(w).Encode(status)
}
