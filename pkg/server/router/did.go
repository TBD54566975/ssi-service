package router

import (
	"context"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"log"
	"net/http"
)

const (
	MethodParam = "method"
	IDParam     = "id"
)

// DIDRouter represents the dependencies required to instantiate a DID-HTTP service
type DIDRouter struct {
	service *did.Service
	logger  *log.Logger
}

// NewDIDRouter creates an HTP router for the DID Service
func NewDIDRouter(s svcframework.Service, l *log.Logger) (*DIDRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	didService, ok := s.(*did.Service)
	if !ok {
		return nil, fmt.Errorf("could not create DID router with service type: %s", s.Type())
	}
	return &DIDRouter{
		service: didService,
		logger:  l,
	}, nil
}

type GetDIDMethodsResponse struct {
	DIDMethods []did.Method `json:"didMethods,omitempty"`
}

func (dr DIDRouter) GetDIDMethods(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	methods := dr.service.GetSupportedMethods()
	response := GetDIDMethodsResponse{DIDMethods: methods.Methods}
	return framework.Respond(ctx, w, response, http.StatusOK)
}

type CreateDIDByMethodRequest struct {
	KeyType crypto.KeyType `json:"keyType" validate:"required"`
}

type CreateDIDByMethodResponse struct {
	DID        didsdk.DIDDocument `json:"did,omitempty"`
	PrivateKey string             `json:"privateKeyBase58,omitempty"`
}

func (dr DIDRouter) CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		dr.logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	var request CreateDIDByMethodRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid create DID request"
		dr.logger.Printf(errors.Wrap(err, errMsg).Error())
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the key type is supported for the method, to tell whether this is a bad req or internal error
	createDIDRequest := did.CreateDIDRequest{Method: did.Method(*method), KeyType: request.KeyType}
	createDIDResponse, err := dr.service.CreateDIDByMethod(createDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		dr.logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusInternalServerError)
	}

	resp := CreateDIDByMethodResponse{
		DID:        createDIDResponse.DID,
		PrivateKey: createDIDResponse.PrivateKey,
	}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetDIDByMethodResponse struct {
	DID didsdk.DIDDocument `json:"did,omitempty"`
}

func (dr DIDRouter) GetDIDByMethod(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "get DID by method request missing method parameter"
		dr.logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("get DID request missing id parameter for method: %s", *method)
		dr.logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDRequest := did.GetDIDRequest{Method: did.Method(*method), ID: *id}
	gotDID, err := dr.service.GetDIDByMethod(getDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DID for method<%s> with id: %s", *method, *id)
		dr.logger.Printf(errors.Wrap(err, errMsg).Error())
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	resp := GetDIDByMethodResponse{DID: gotDID.DID}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}
