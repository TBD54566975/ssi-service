package router

import (
	"context"
	"fmt"
	"net/http"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/util"
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
	return &DIDRouter{service: didService}, nil
}

type GetDIDMethodsResponse struct {
	DIDMethods []didsdk.Method `json:"method,omitempty"`
}

// GetDIDMethods godoc
//
// @Summary     Get DID Methods
// @Description Get supported DID method
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Success     200 {object} GetDIDMethodsResponse
// @Router      /v1/dids [get]
func (dr DIDRouter) GetDIDMethods(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	methods := dr.service.GetSupportedMethods()
	response := GetDIDMethodsResponse{DIDMethods: methods.Methods}
	return framework.Respond(ctx, w, response, http.StatusOK)
}

type CreateDIDByMethodRequest struct {
	// Identifies the cryptographic algorithm family to use when generating this key.
	// One of the following: "Ed25519", "X25519", "secp256k1", "P-224","P-256","P-384", "P-521", "RSA"
	KeyType crypto.KeyType `json:"keyType" validate:"required"`

	// Options for creating the DID. Implementation dependent on the method.
	Options any `json:"options,omitempty"`
}

type CreateDIDByMethodResponse struct {
	DID              didsdk.Document `json:"did,omitempty"`
	PrivateKeyBase58 string          `json:"privateKeyBase58,omitempty"`
	KeyType          crypto.KeyType  `json:"keyType,omitempty"`
}

// CreateDIDByMethod godoc
//
// @Summary     Create DID Document
// @Description Creates a DID document with the given method. The document created is stored internally and can be
// @Description retrieved using the GetOperation. Method dependent registration (for example, DID web registration)
// @Description is left up to the clients of this API.
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateDIDByMethodRequest true "request body"
// @Param       method  path     string                   true "Method"
// @Success     201     {object} CreateDIDByMethodResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/dids/{method} [put]
func (dr DIDRouter) CreateDIDByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	var request CreateDIDByMethodRequest
	invalidCreateDIDRequest := "invalid create DID request"
	if err := framework.Decode(r, &request); err != nil {
		errMsg := invalidCreateDIDRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreateDIDRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	// TODO(gabe) check if the key type is supported for the method, to tell whether this is a bad req or internal error
	createDIDRequest, err := toCreateDIDRequest(didsdk.Method(*method), request)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, invalidCreateDIDRequest), http.StatusBadRequest)
	}
	createDIDResponse, err := dr.service.CreateDIDByMethod(ctx, *createDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateDIDByMethodResponse{DID: createDIDResponse.DID}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

// toCreateDIDRequest converts CreateDIDByMethodRequest to did.CreateDIDRequest, parsing options according to method
func toCreateDIDRequest(m didsdk.Method, request CreateDIDByMethodRequest) (*did.CreateDIDRequest, error) {
	createRequest := did.CreateDIDRequest{
		Method:  m,
		KeyType: request.KeyType,
	}

	// check if options are present
	if request.Options == nil {
		return &createRequest, nil
	}

	// parse options according to method
	switch m {
	case didsdk.IONMethod:
		var opts did.CreateIONDIDOptions
		if err := optionsToType(request.Options, &opts); err != nil {
			return nil, errors.Wrap(err, "parsing ion options")
		}
		createRequest.Options = opts
	case didsdk.WebMethod:
		var opts did.CreateWebDIDOptions
		if err := optionsToType(request.Options, &opts); err != nil {
			return nil, errors.Wrap(err, "parsing web options")
		}
		createRequest.Options = opts
	default:
		if request.Options != nil {
			return nil, fmt.Errorf("invalid options for method<%s>", m)
		}
	}
	return &createRequest, nil
}

// optionsToType converts options to the given type where options is a map[string]interface{} and optionType
// is a pointer to an empty struct of the desired type
func optionsToType(options any, out any) error {
	if !util.IsStructPtr(out) {
		return fmt.Errorf("output object must be a pointer to a struct")
	}
	optionBytes, err := json.Marshal(options)
	if err != nil {
		return errors.Wrap(err, "marshalling options")
	}
	if err = json.Unmarshal(optionBytes, out); err != nil {
		return errors.Wrap(err, "unmarshalling options")
	}
	return nil
}

type GetDIDByMethodResponse struct {
	DID didsdk.Document `json:"did,omitempty"`
}

// GetDIDByMethod godoc
//
// @Summary     Get DID
// @Description Get DID by method
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateDIDByMethodRequest true "request body"
// @Param       method  path     string                   true "Method"
// @Param       id      path     string                   true "ID"
// @Success     200     {object} GetDIDByMethodResponse
// @Failure     400     {string} string "Bad request"
// @Router      /v1/dids/{method}/{id} [get]
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
	getDIDRequest := did.GetDIDRequest{Method: didsdk.Method(*method), ID: *id}
	gotDID, err := dr.service.GetDIDByMethod(ctx, getDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DID for method<%s> with id: %s", *method, *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetDIDByMethodResponse{DID: gotDID.DID}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetDIDsByMethodResponse struct {
	DIDs []didsdk.Document `json:"dids,omitempty"`
}

type GetDIDsRequest struct {
	// A standard filter expression conforming to https://google.aip.dev/160.
	// Not implemented yet.
	Filter string `json:"filter"`
}

// GetDIDsByMethod godoc
//
// @Summary     Get DIDs
// @Description Get DIDs by method
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       request body     GetDIDsRequest true "request body"
// @Success     200     {object} GetDIDsByMethodResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/dids [get]
func (dr DIDRouter) GetDIDsByMethod(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "get DIDs by method request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDsRequest := did.GetDIDsRequest{Method: didsdk.Method(*method)}
	gotDIDs, err := dr.service.GetDIDsByMethod(ctx, getDIDsRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DIDs for method: %s", *method)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := GetDIDsByMethodResponse{DIDs: gotDIDs.DIDs}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type ResolveDIDResponse struct {
	ResolutionMetadata  *didsdk.ResolutionMetadata `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.Document           `json:"didDocument"`
	DIDDocumentMetadata *didsdk.DocumentMetadata   `json:"didDocumentMetadata,omitempty"`
}

// SoftDeleteDIDByMethod godoc
// @Description When this is called with the correct did method and id it will flip the softDelete flag to true for the db entry.
// @Description A user can still get the did if they know the DID ID, and the did keys will still exist, but this did will not show up in the GetDIDsByMethod call
// @Description This facilitates a clean SSI-Service Admin UI but not leave any hanging VCs with inaccessible hanging DIDs.
// @Summary     Soft Delete DID
// @Description Soft Deletes DID by method
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       method  path     string                   true "Method"
// @Param       id      path     string                   true "ID"
// @Success     204     {string} string "No Content"
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/dids/{method}/{id} [delete]
func (dr DIDRouter) SoftDeleteDIDByMethod(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	if method == nil {
		errMsg := "soft delete DID by method request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("soft delete DID request missing id parameter for method: %s", *method)
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	deleteDIDRequest := did.DeleteDIDRequest{Method: didsdk.Method(*method), ID: *id}
	if err := dr.service.SoftDeleteDIDByMethod(ctx, deleteDIDRequest); err != nil {
		errMsg := fmt.Sprintf("could not soft delete DID with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusNoContent)
}

// ResolveDID godoc
//
// @Summary     Resolve a DID
// @Description Resolve a DID that may not be stored in this service
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} ResolveDIDResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/dids/resolver/{id} [get]
func (dr DIDRouter) ResolveDID(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "get DID request missing id parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	resolveDIDRequest := did.ResolveDIDRequest{DID: *id}
	resolvedDID, err := dr.service.ResolveDID(resolveDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DID with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := ResolveDIDResponse{ResolutionMetadata: resolvedDID.ResolutionMetadata, DIDDocument: resolvedDID.DIDDocument, DIDDocumentMetadata: resolvedDID.DIDDocumentMetadata}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}
