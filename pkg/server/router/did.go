package router

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/did"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
)

const (
	MethodParam  = "method"
	IDParam      = "id"
	DeletedParam = "deleted"
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
func (dr DIDRouter) GetDIDMethods(c *gin.Context) {
	methods := dr.service.GetSupportedMethods()
	response := GetDIDMethodsResponse{DIDMethods: methods.Methods}
	framework.Respond(c, response, http.StatusOK)
}

type CreateDIDByMethodRequest struct {
	// Identifies the cryptographic algorithm family to use when generating this key.
	// One of the following: "Ed25519", "X25519", "secp256k1", "P-224","P-256","P-384", "P-521", "RSA"
	KeyType crypto.KeyType `json:"keyType" validate:"required"`

	// Options for creating the DID. Implementation dependent on the method.
	Options any `json:"options,omitempty"`
}

type CreateDIDByMethodResponse struct {
	DID didsdk.Document `json:"did,omitempty"`
}

// CreateDIDByMethod godoc
//
// @Summary     Create DID Document
// @Description Creates a fully custodial DID document with the given method. The document created is stored internally
// @Description and can be retrieved using the GetOperation. Method dependent registration (for example, DID web
// @Description registration) is left up to the clients of this API. The private key(s) created by the method are stored
// @Description internally never leave the service boundary.
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateDIDByMethodRequest true "request body"
// @Param       method  path     string                   true "Method"
// @Success     201     {object} CreateDIDByMethodResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/dids/{method} [put]
func (dr DIDRouter) CreateDIDByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		framework.RespondLoggingError(c, framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest))
		return
	}

	var request CreateDIDByMethodRequest
	invalidCreateDIDRequest := "invalid create DID request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.RespondLoggingError(c, framework.NewRequestErrorWithMsg(err, invalidCreateDIDRequest, http.StatusBadRequest))
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.RespondLoggingError(c, framework.NewRequestErrorWithMsg(err, invalidCreateDIDRequest, http.StatusBadRequest))
		return
	}

	// TODO(gabe) check if the key type is supported for the method, to tell whether this is a bad req or internal error
	createDIDRequest, err := toCreateDIDRequest(didsdk.Method(*method), request)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		framework.RespondLoggingError(c, framework.NewRequestErrorWithMsg(err, invalidCreateDIDRequest+": "+errMsg, http.StatusBadRequest))
		return
	}
	createDIDResponse, err := dr.service.CreateDIDByMethod(c, *createDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		framework.RespondLoggingError(c, framework.NewRequestErrorWithMsg(err, errMsg, http.StatusInternalServerError))
		return
	}

	resp := CreateDIDByMethodResponse{DID: createDIDResponse.DID}
	framework.Respond(c, resp, http.StatusCreated)
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
func (dr DIDRouter) GetDIDByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "get DID by method request missing method parameter"
		logrus.Error(errMsg)
		framework.RespondError(c, framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest))
	}
	id := framework.GetParam(c, IDParam)
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
// @Description Get DIDs by method. Checks for an optional "deleted=true" query parameter, which exclusively returns DIDs that have been "Soft Deleted".
// @Tags        DecentralizedIdentityAPI
// @Accept      json
// @Produce     json
// @Param       deleted  query    boolean false "When true, returns soft-deleted DIDs. Otherwise, returns DIDs that have not been soft-deleted. Default is false."
// @Param       request body     GetDIDsRequest true "request body"
// @Success     200     {object} GetDIDsByMethodResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/dids/{method} [get]
func (dr DIDRouter) GetDIDsByMethod(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	method := framework.GetParam(ctx, MethodParam)
	deleted := framework.GetQueryValue(r, DeletedParam)
	if method == nil {
		errMsg := "get DIDs by method request missing method parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}
	getIsDeleted := false
	if deleted != nil {
		checkDeleted, err := strconv.ParseBool(*deleted)
		getIsDeleted = checkDeleted

		if err != nil {
			errMsg := "get DIDs by method request encountered a problem with the `deleted` query param"
			logrus.Error(errMsg)
			return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
		}
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDsRequest := did.GetDIDsRequest{Method: didsdk.Method(*method), Deleted: getIsDeleted}
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
	ResolutionMetadata  *resolution.ResolutionMetadata `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.Document               `json:"didDocument"`
	DIDDocumentMetadata *resolution.DocumentMetadata   `json:"didDocumentMetadata,omitempty"`
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
