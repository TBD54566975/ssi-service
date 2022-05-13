package router

import (
	"context"
	"github.com/goccy/go-json"
	"net/http"
)

type GetHealthCheckResponse struct {
	Status string `json:"status"`
}

const (
	HealthOK string = "OK"
)

// Health is a simple handler that always responds with a 200 OK
func Health(_ context.Context, w http.ResponseWriter, _ *http.Request) error {
	status := GetHealthCheckResponse{Status: HealthOK}
	return json.NewEncoder(w).Encode(status)
}
