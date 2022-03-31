package server

import (
	"context"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"net/http"
)

type GetDIDMethodsRequest struct{}

func GetDIDMethods(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "GET DID METHODS",
	}

	return framework.Respond(ctx, w, status, http.StatusOK)
}

type CreateDIDByMethodRequest struct{}

func CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "CREATE DID",
	}

	return framework.Respond(ctx, w, status, http.StatusOK)
}

type GetDIDByMethodRequest struct{}

func GetDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "GET DIDS",
	}

	return framework.Respond(ctx, w, status, http.StatusOK)
}
