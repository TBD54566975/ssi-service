package server

import (
	"context"
	"fmt"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"net/http"
)

const (
	MethodParam = "method"
	IDParam     = "id"
)

type GetDIDMethodsResponse struct {
	DIDMethods []string `json:"did_methods,omitempty"`
}

func GetDIDMethods(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	status := struct {
		Status string
	}{
		Status: "GET DID METHODS",
	}

	return framework.Respond(ctx, w, status, http.StatusOK)
}

type CreateDIDByMethodResponse struct {
	DID interface{} `json:"did,omitempty"`
}

func CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := getParam(ctx, MethodParam)
	if method == nil {
		return framework.NewRequestErrorMsg("create DID request missing method parameter", http.StatusBadRequest)
	}
	return framework.Respond(ctx, w, nil, http.StatusOK)
}

type GetDIDByMethodRequest struct {
	DID interface{} `json:"did,omitempty"`
}

func GetDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := getParam(ctx, MethodParam)
	if method == nil {
		return framework.NewRequestErrorMsg("create DID request missing method parameter", http.StatusBadRequest)
	}
	id := getParam(ctx, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("get DID request missing id parameter for method: %s", *method)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
