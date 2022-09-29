package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	MethodParam = "method"
	IDParam     = "id"
)

// DIDRouter represents the dependencies required to instantiate a DID-HTTP service
type DIDRouter struct {
	service *did.Service
}

// NewDIDRouter creates an HTP router for the DID Service
func NewDIDRouter(s svcframework.Service) (*DIDRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	didService, ok := s.(*did.Service)
	if !ok {
		return nil, fmt.Errorf("could not create DID router with service type: %s", s.Type())
	}
	return &DIDRouter{
		service: didService,
	}, nil
}

type GetDIDMethodsResponse struct {
	DIDMethods []did.Method `json:"didMethods,omitempty"`
}

// GetDIDMethods godoc
// @Summary      Get DID Methods
// @Description  Get supported DID methods
// @Tags         DecentralizedIdentityAPI
// @Accept       json
// @Produce      json
// @Success      200  {object}  GetDIDMethodsResponse
// @Router       /v1/dids [get]
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

// CreateDIDByMethod godoc
// @Summary      Create DID
// @Description  create DID by method
// @Tags         DecentralizedIdentityAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreateDIDByMethodRequest  true  "request body"
// @Param        method   path      string                    true  "Method"
// @Success      201      {object}  CreateDIDByMethodResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/dids/{method} [put]
func (dr DIDRouter) CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	var request CreateDIDByMethodRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid create DID request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	// TODO(gabe) check if the key type is supported for the method, to tell whether this is a bad req or internal error
	createDIDRequest := did.CreateDIDRequest{Method: did.Method(*method), KeyType: request.KeyType}
	createDIDResponse, err := dr.service.CreateDIDByMethod(createDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
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

// GetDIDByMethod godoc
// @Summary      Get DID
// @Description  Get DID by method
// @Tags         DecentralizedIdentityAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreateDIDByMethodRequest  true  "request body"
// @Param        method   path      string                    true  "Method"
// @Param        id       path      string                    true  "ID"
// @Success      200      {object}  GetDIDByMethodResponse
// @Failure      400      {string}  string  "Bad request"
// @Router       /v1/dids/{method}/{id} [get]
func (dr DIDRouter) GetDIDByMethod(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "get DID by method request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("get DID request missing id parameter for method: %s", *method)
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDRequest := did.GetDIDRequest{Method: did.Method(*method), ID: *id}
	gotDID, err := dr.service.GetDIDByMethod(getDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DID for method<%s> with id: %s", *method, *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetDIDByMethodResponse{DID: gotDID.DID}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetDIDsByMethodResponse struct {
	DIDs []didsdk.DIDDocument `json:"dids,omitempty"`
}

// GetDIDsByMethod godoc
// @Summary      Get DIDs
// @Description  Get DIDs by method
// @Tags         DecentralizedIdentityAPI
// @Accept       json
// @Produce      json
// @Param        method   path      string                    true  "Method"
// @Success      200      {object}  GetDIDsByMethodResponse
// @Failure      400      {string}  string  "Bad request"
// @Router       /v1/dids/{method} [get]
func (dr DIDRouter) GetDIDsByMethod(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "get DIDs by method request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDsRequest := did.GetDIDsRequest{Method: did.Method(*method)}
	gotDIDs, err := dr.service.GetDIDsByMethod(getDIDsRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DIDs for method: %s", *method)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetDIDsByMethodResponse{DIDs: gotDIDs.DIDs}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}
