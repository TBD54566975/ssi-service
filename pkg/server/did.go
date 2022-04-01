package server

import (
	"context"
	"fmt"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/services/did"
	"net/http"
)

const (
	MethodParam = "method"
	IDParam     = "id"
)

// DIDServiceHTTP represents the dependencies required to instantiate a DID-HTTP service
type DIDServiceHTTP struct {
	did.Service
}

type GetDIDMethodsResponse struct {
	DIDMethods []string `json:"didMethods,omitempty"`
}

func (s DIDServiceHTTP) GetDIDMethods(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
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

func (s DIDServiceHTTP) CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		return framework.NewRequestErrorMsg("create DID request missing method parameter", http.StatusBadRequest)
	}
	return framework.Respond(ctx, w, nil, http.StatusOK)
}

type GetDIDByMethodRequest struct {
	DID interface{} `json:"did,omitempty"`
}

func (s DIDServiceHTTP) GetDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		return framework.NewRequestErrorMsg("create DID request missing method parameter", http.StatusBadRequest)
	}
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("get DID request missing id parameter for method: %s", *method)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
