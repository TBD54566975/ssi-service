package router

import (
	"context"
	"net/http"

	"github.com/goccy/go-json"
)

type GetHealthCheckResponse struct {
	// Status is always equal to `OK`.
	Status string `json:"status"`
}

const (
	HealthOK string = "OK"
)

// Health godoc
//
// @Summary     Health Check
// @Description Health is a simple handler that always responds with a 200 OK
// @Tags        HealthCheck
// @Accept      json
// @Produce     json
// @Success     200 {object} GetHealthCheckResponse
// @Router      /health [get]
func Health(_ context.Context, w http.ResponseWriter, _ *http.Request) error {
	status := GetHealthCheckResponse{Status: HealthOK}
	return json.NewEncoder(w).Encode(status)
}
