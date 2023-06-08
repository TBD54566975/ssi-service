package router

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
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
	MethodParam    = "method"
	IDParam        = "id"
	DeletedParam   = "deleted"
	PageSizeParam  = "pageSize"
	PageTokenParam = "pageToken"
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

type ListDIDMethodsResponse struct {
	DIDMethods []didsdk.Method `json:"method,omitempty"`
}

// ListDIDMethods godoc
//
//	@Summary		List DID Methods
//	@Description	Get the list of supported DID methods
//	@Tags			DecentralizedIdentityAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListDIDMethodsResponse
//	@Router			/v1/dids [get]
func (dr DIDRouter) ListDIDMethods(c *gin.Context) {
	methods := dr.service.GetSupportedMethods()
	response := ListDIDMethodsResponse{DIDMethods: methods.Methods}
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
//	@Summary		Create DID Document
//	@Description	Creates a fully custodial DID document with the given method. The document created is stored internally
//	@Description	and can be retrieved using the GetOperation. Method dependent registration (for example, DID web
//	@Description	registration) is left up to the clients of this API. The private key(s) created by the method are stored
//	@Description	internally never leave the service boundary.
//	@Tags			DecentralizedIdentityAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateDIDByMethodRequest	true	"request body"
//	@Param			method	path		string						true	"Method"
//	@Success		201		{object}	CreateDIDByMethodResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/dids/{method} [put]
func (dr DIDRouter) CreateDIDByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	var request CreateDIDByMethodRequest
	invalidCreateDIDRequest := "invalid create DID request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateDIDRequest, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateDIDRequest, http.StatusBadRequest)
		return
	}

	// TODO(gabe) check if the key type is supported for the method, to tell whether this is a bad req or internal error
	createDIDRequest, err := toCreateDIDRequest(didsdk.Method(*method), request)
	if err != nil {
		errMsg := fmt.Sprintf("%s: could not create DID for method<%s> with key type: %s", invalidCreateDIDRequest, *method, request.KeyType)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}
	createDIDResponse, err := dr.service.CreateDIDByMethod(c, *createDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not create DID for method<%s> with key type: %s", *method, request.KeyType)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
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
	DID didsdk.Document `json:"did"`
}

// GetDIDByMethod godoc
//
//	@Summary		Get DID
//	@Description	Get DID by method
//	@Tags			DecentralizedIdentityAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateDIDByMethodRequest	true	"request body"
//	@Param			method	path		string						true	"Method"
//	@Param			id		path		string						true	"ID"
//	@Success		200		{object}	GetDIDByMethodResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Router			/v1/dids/{method}/{id} [get]
func (dr DIDRouter) GetDIDByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "get DID by method request missing method parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("get DID request missing id parameter for method: %s", *method)
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDRequest := did.GetDIDRequest{Method: didsdk.Method(*method), ID: *id}
	gotDID, err := dr.service.GetDIDByMethod(c, getDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DID for method<%s> with id: %s", *method, *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	resp := GetDIDByMethodResponse{DID: gotDID.DID}
	framework.Respond(c, resp, http.StatusOK)
}

type ListDIDsByMethodResponse struct {
	DIDs []didsdk.Document `json:"dids,omitempty"`

	// Pagination token to retrieve the next page of results. If the value is "", it means no further results for the request.
	NextPageToken string `json:"nextPageToken"`
}

type GetDIDsRequest struct {
	// A standard filter expression conforming to https://google.aip.dev/160.
	// Not implemented yet.
	Filter string `json:"filter,omitempty"`
}

type PageToken struct {
	EncodedQuery  string
	NextPageToken string
}

// ListDIDsByMethod godoc
//
//	@Summary		List DIDs
//	@Description	List DIDs by method. Checks for an optional "deleted=true" query parameter, which exclusively returns DIDs that have been "Soft Deleted".
//	@Tags			DecentralizedIdentityAPI
//	@Accept			json
//	@Produce		json
//	@Param			deleted		query		boolean	false	"When true, returns soft-deleted DIDs. Otherwise, returns DIDs that have not been soft-deleted. Default is false."
//	@Param			pageSize	query		number	false	"Hint to the server of the maximum elements to return. More may be returned. When not set, the server will return all elements."
//	@Param			pageToken	query		string	false	"Used to indicate to the server to return a specific page of the list results. Must match a previous requests' `nextPageToken`."
//	@Success		200			{object}	ListDIDsByMethodResponse
//	@Failure		400			{string}	string	"Bad request"
//	@Failure		500			{string}	string	"Internal server error"
//	@Router			/v1/dids/{method} [get]
func (dr DIDRouter) ListDIDsByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "list DIDs by method request missing method parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	getIsDeleted := false
	deleted := framework.GetQueryValue(c, DeletedParam)
	if deleted != nil {
		checkDeleted, err := strconv.ParseBool(*deleted)
		getIsDeleted = checkDeleted

		if err != nil {
			errMsg := "list DIDs by method request encountered a problem with the `deleted` query param"
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return
		}
	}
	// TODO(gabe) check if the method is supported, to tell whether this is a bad req or internal error
	// TODO(gabe) differentiate between internal errors and not found DIDs
	getDIDsRequest := did.ListDIDsRequest{Method: didsdk.Method(*method), Deleted: getIsDeleted}

	pageSizeStr := framework.GetParam(c, PageSizeParam)

	if pageSizeStr != nil {
		pageSize, err := strconv.Atoi(*pageSizeStr)
		if err != nil {
			errMsg := fmt.Sprintf("list DIDs by method request encountered a problem with the %q query param", PageSizeParam)
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return
		}
		getDIDsRequest.PageSize = &pageSize
	}

	queryPageToken := framework.GetParam(c, PageTokenParam)
	if queryPageToken != nil {
		errMsg := "token value cannot be decoded"
		tokenData, err := base64.RawURLEncoding.DecodeString(*queryPageToken)
		if err != nil {
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return
		}
		var pageToken PageToken
		if err := json.Unmarshal(tokenData, &pageToken); err != nil {
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return
		}
		pageTokenValues, err := url.ParseQuery(pageToken.EncodedQuery)
		if err != nil {
			framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
			return
		}

		query := pageTokenQuery(c)
		if !reflect.DeepEqual(pageTokenValues, query) {
			logrus.Warnf("expected query from token to be equal to query from request. token: %v\nrequest%v", pageTokenValues, query)
			framework.LoggingRespondErrMsg(c, "page token must be for the same query", http.StatusBadRequest)
			return
		}
		getDIDsRequest.PageToken = &pageToken.NextPageToken
	}

	listResp, err := dr.service.ListDIDsByMethod(c, getDIDsRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DIDs for method: %s", *method)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := ListDIDsByMethodResponse{
		DIDs: listResp.DIDs,
	}
	if listResp.NextPageToken != "" {
		tokenQuery := pageTokenQuery(c)
		pageToken := PageToken{
			EncodedQuery:  tokenQuery.Encode(),
			NextPageToken: listResp.NextPageToken,
		}
		nextPageTokenData, err := json.Marshal(pageToken)
		if err != nil {
			framework.LoggingRespondErrWithMsg(c, err, "marshalling page token", http.StatusInternalServerError)
			return
		}
		resp.NextPageToken = base64.RawURLEncoding.EncodeToString(nextPageTokenData)
	}
	framework.Respond(c, resp, http.StatusOK)
}

func pageTokenQuery(c *gin.Context) url.Values {
	query := c.Request.URL.Query()
	delete(query, PageTokenParam)
	delete(query, PageSizeParam)
	return query
}

type ResolveDIDResponse struct {
	ResolutionMetadata  *resolution.Metadata         `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.Document             `json:"didDocument"`
	DIDDocumentMetadata *resolution.DocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

// SoftDeleteDIDByMethod godoc
//
//	@Description	When this is called with the correct did method and id it will flip the softDelete flag to true for the db entry.
//	@Description	A user can still get the did if they know the DID ID, and the did keys will still exist, but this did will not show up in the ListDIDsByMethod call
//	@Description	This facilitates a clean SSI-Service Admin UI but not leave any hanging VCs with inaccessible hanging DIDs.
//	@Summary		Soft Delete DID
//	@Description	Soft Deletes DID by method
//	@Tags			DecentralizedIdentityAPI
//	@Accept			json
//	@Produce		json
//	@Param			method	path		string	true	"Method"
//	@Param			id		path		string	true	"ID"
//	@Success		204		{string}	string	"No Content"
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/dids/{method}/{id} [delete]
func (dr DIDRouter) SoftDeleteDIDByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "soft delete DID by method request missing method parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("soft delete DID request missing id parameter for method: %s", *method)
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	deleteDIDRequest := did.DeleteDIDRequest{Method: didsdk.Method(*method), ID: *id}
	if err := dr.service.SoftDeleteDIDByMethod(c, deleteDIDRequest); err != nil {
		errMsg := fmt.Sprintf("could not soft delete DID with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
}

// ResolveDID godoc
//
//	@Summary		Resolve a DID
//	@Description	Resolve a DID that may not be stored in this service
//	@Tags			DecentralizedIdentityAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	ResolveDIDResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/dids/resolver/{id} [get]
func (dr DIDRouter) ResolveDID(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "get DID request missing id parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	resolveDIDRequest := did.ResolveDIDRequest{DID: *id}
	resolvedDID, err := dr.service.ResolveDID(resolveDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DID with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}

	resp := ResolveDIDResponse{ResolutionMetadata: resolvedDID.ResolutionMetadata, DIDDocument: resolvedDID.DIDDocument, DIDDocumentMetadata: resolvedDID.DIDDocumentMetadata}
	framework.Respond(c, resp, http.StatusOK)
}
