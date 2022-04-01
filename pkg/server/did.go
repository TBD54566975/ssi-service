package server

import (
	"context"
	"fmt"
	"github.com/TBD54566975/did-sdk/crypto"
	"github.com/tbd54566975/vc-service/pkg/server/framework"
	"github.com/tbd54566975/vc-service/pkg/service/did"
	"log"
	"net/http"
)

const (
	MethodParam = "method"
	IDParam     = "id"
)

// DIDServiceHTTP represents the dependencies required to instantiate a DID-HTTP service
type DIDServiceHTTP struct {
	did.Service
	*log.Logger
}

type GetDIDMethodsResponse struct {
	DIDMethods []did.Method `json:"didMethods,omitempty"`
}

func (s DIDServiceHTTP) GetDIDMethods(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	response := GetDIDMethodsResponse{DIDMethods: s.GetSupportedMethods()}
	return framework.Respond(ctx, w, response, http.StatusOK)
}

type CreateDIDByMethodRequest struct {
	KeyType crypto.KeyType `json:"keyType" validate:"required"`
}

type CreateDIDByMethodResponse struct {
	DID interface{} `json:"did,omitempty"`
}

func (s DIDServiceHTTP) CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		s.Logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	var request CreateDIDByMethodRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "could not decode method request"
		s.Logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	handler, err := s.GetHandler(did.Method(*method))
	if err != nil {
		errMsg := fmt.Sprintf("could not get handler for method<%s>", *method)
		s.Logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the key type is supported for the method, to tell whether this is a bad req or internal error
	createDIDResponse, err := handler.CreateDID(did.CreateDIDRequest{KeyType: "nil"})
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, "nil")
		s.Logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, *createDIDResponse, http.StatusOK)
}

type GetDIDByMethodRequest struct {
	DID interface{} `json:"did,omitempty"`
}

func (s DIDServiceHTTP) GetDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		s.Logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("get DID request missing id parameter for method: %s", *method)
		s.Logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
