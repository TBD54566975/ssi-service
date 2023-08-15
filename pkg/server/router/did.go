package router

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/ion"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	"github.com/tbd54566975/ssi-service/pkg/server/pagination"
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

type ListDIDMethodsResponse struct {
	DIDMethods []didsdk.Method `json:"method,omitempty"`
}

// ListDIDMethods godoc
//
//	@Summary		List DID methods
//	@Description	Get the list of supported DID methods
//	@Tags			DecentralizedIdentifiers
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
	KeyType crypto.KeyType `json:"keyType" validate:"required"`

	// Options for creating the DID. Implementation dependent on the method.
	Options any `json:"options,omitempty"`
}

type CreateDIDByMethodResponse struct {
	DID didsdk.Document `json:"did,omitempty"`
}

// CreateDIDByMethod godoc
//
//	@Summary		Create a DID Document
//	@Description	Creates a fully custodial DID document with the given method. The document created is stored internally
//	@Description	and can be retrieved using the GetOperation. Method dependent registration (for example, DID web
//	@Description	registration) is left up to the clients of this API. The private key(s) created by the method are stored
//	@Description	internally never leave the service boundary.
//	@Tags			DecentralizedIdentifiers
//	@Accept			json
//	@Produce		json
//	@Param			method	path		string														true	"Method"
//	@Param			request	body		CreateDIDByMethodRequest{options=did.CreateIONDIDOptions}	true	"request body"
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

type StateChange struct {
	ServicesToAdd        []didsdk.Service `json:"servicesToAdd,omitempty"`
	ServiceIDsToRemove   []string         `json:"serviceIdsToRemove,omitempty"`
	PublicKeysToAdd      []ion.PublicKey  `json:"publicKeysToAdd,omitempty"`
	PublicKeyIDsToRemove []string         `json:"publicKeyIdsToRemove"`
}

type UpdateDIDByMethodRequest struct {
	// Expected to be populated when `method == "ion"`. Describes the changes that are requested.
	StateChange StateChange `json:"stateChange" validate:"required"`
}

type UpdateDIDByMethodResponse struct {
	DID didsdk.Document `json:"did,omitempty"`
}

// UpdateDIDByMethod godoc
//
//	@Summary		Updates a DID document.
//	@Description	Updates a DID for which SSI is the custodian. The DID must have been previously created by calling
//	@Description	the "Create DID Document" endpoint. Currently, only ION dids support updates.
//	@Tags			DecentralizedIdentifiers
//	@Accept			json
//	@Produce		json
//	@Param			method	path		string						true	"Method"
//	@Param			id		path		string						true	"ID"
//	@Param			request	body		UpdateDIDByMethodRequest	true	"request body"
//	@Success		200		{object}	UpdateDIDByMethodResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/dids/{method}/{id} [put]
func (dr DIDRouter) UpdateDIDByMethod(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "update DID by method request missing method parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	if *method != didsdk.IONMethod.String() {
		framework.LoggingRespondErrMsg(c, "ion is the only method supported", http.StatusBadRequest)
	}

	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := fmt.Sprintf("update DID request missing id parameter for method: %s", *method)
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	var request UpdateDIDByMethodRequest
	invalidRequest := "invalid update DID request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidRequest, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidRequest, http.StatusBadRequest)
		return
	}

	updateDIDRequest, err := toUpdateIONDIDRequest(*id, request)
	if err != nil {
		errMsg := fmt.Sprintf("%s: could not update DID for method<%s>", invalidRequest, *method)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
		return
	}
	updateIONDIDResponse, err := dr.service.UpdateIONDID(c, *updateDIDRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not update DID for method<%s>", *method)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := CreateDIDByMethodResponse{DID: updateIONDIDResponse.DID}
	framework.Respond(c, resp, http.StatusOK)
}

func toUpdateIONDIDRequest(id string, request UpdateDIDByMethodRequest) (*did.UpdateIONDIDRequest, error) {
	didION := ion.ION(id)
	if !didION.IsValid() {
		return nil, errors.Errorf("invalid ion did %s", id)
	}
	return &did.UpdateIONDIDRequest{
		DID: didION,
		StateChange: ion.StateChange{
			ServicesToAdd:        request.StateChange.ServicesToAdd,
			ServiceIDsToRemove:   request.StateChange.ServiceIDsToRemove,
			PublicKeysToAdd:      request.StateChange.PublicKeysToAdd,
			PublicKeyIDsToRemove: request.StateChange.PublicKeyIDsToRemove,
		},
	}, nil
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
//	@Summary		Get a DID
//	@Description	Gets a DID Document by its DID ID
//	@Tags			DecentralizedIdentifiers
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

// ListDIDsByMethod godoc
//
//	@Summary		List DIDs by method
//	@Description	List DIDs by method. Checks for an optional "deleted=true" query parameter, which exclusively
//	@Description	returns DIDs that have been "Soft Deleted".
//	@Tags			DecentralizedIdentifiers
//	@Accept			json
//	@Produce		json
//	@Param			method		path		string	true	"Method must be one returned by GET /v1/dids"
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
	getDIDsRequest := did.ListDIDsRequest{
		Method:  didsdk.Method(*method),
		Deleted: getIsDeleted,
	}
	var pageRequest pagination.PageRequest
	if pagination.ParsePaginationQueryValues(c, &pageRequest) {
		return
	}
	getDIDsRequest.PageRequest = pageRequest.ToServicePage()

	listResp, err := dr.service.ListDIDsByMethod(c, getDIDsRequest)
	if err != nil {
		errMsg := fmt.Sprintf("could not get DIDs for method: %s", *method)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := ListDIDsByMethodResponse{
		DIDs: listResp.DIDs,
	}
	if pagination.MaybeSetNextPageToken(c, listResp.NextPageToken, &resp.NextPageToken) {
		return
	}
	framework.Respond(c, resp, http.StatusOK)
}

type ResolveDIDResponse struct {
	ResolutionMetadata  *resolution.Metadata         `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.Document             `json:"didDocument"`
	DIDDocumentMetadata *resolution.DocumentMetadata `json:"didDocumentMetadata,omitempty"`
}

// DeleteDIDByMethod godoc
//
//	@Summary		Deletes a DID
//	@Description	Soft deletes and deactivates (when applicable) a DID for which SSI is the custodian. The DID must have
//	@Description	been previously created by calling	the "Create DID Document" endpoint. The effects of Deleting a DID depend on it's DID Method.
//	@Description
//	@Description	When this is called, it will flip the `softDelete` flag to true for the db entry.
//	@Description	A user can still get the did if they know the DID ID, and the did keys will still exist, but this did will not show up in the ListDIDsByMethod call
//	@Description	This facilitates a clean SSI-Service Admin UI but not leave any hanging VCs with inaccessible hanging DIDs.
//	@Description
//	@Description	For a DID who's DID Method is `ion`, deactivation is also performed. The effects of deactivating a DID include:
//	@Description
//	@Description	* The `didDocumentMetadata.deactivated` property will be set to `true` after
//	@Description	doing DID resolution (e.g. by calling the `v1/dids/resolution/<did>` endpoint).
//	@Description	* All the DID Document properties will be removed, except for the `id` and `@context`. In practical terms, this
//	@Description	means that no counterparty will be able to obtain verification material from this DID.
//	@Description	* All keys stored by SSI service that are related to this DID (i.e. update, recovery, verification) will be revoked.
//	@Description
//	@Description	Please note that deactivation of an `ion` DID is an irreversible operation. For more details, refer to the sidetree spec at https://identity.foundation/sidetree/spec/#deactivate
//	@Tags			DecentralizedIdentifiers
//	@Accept			json
//	@Produce		json
//	@Param			method	path		string	true	"Method"
//	@Param			id		path		string	true	"ID"
//	@Success		204		{string}	string	"No Content"
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/dids/{method}/{id} [delete]
func (dr DIDRouter) DeleteDIDByMethod(c *gin.Context) {
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
	if err := dr.service.DeleteDIDByMethod(c, deleteDIDRequest); err != nil {
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
//	@Tags			DecentralizedIdentifiers
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

type BatchCreateDIDsRequest struct {
	// Required. The list of create credential requests. Cannot be more than {{.Services.DIDConfig.BatchCreateMaxItems}} items.
	Requests []CreateDIDByMethodRequest `json:"requests" maxItems:"100" validate:"required,dive"`
}

func (r BatchCreateDIDsRequest) toServiceRequest(m didsdk.Method) (*did.BatchCreateDIDsRequest, error) {
	var req did.BatchCreateDIDsRequest
	for _, routerReq := range r.Requests {
		serviceReq, err := toCreateDIDRequest(m, routerReq)
		if err != nil {
			return &req, err
		}
		req.Requests = append(req.Requests, *serviceReq)
	}
	return &req, nil
}

type BatchCreateDIDsResponse struct {
	// The DID documents created.
	DIDs []didsdk.Document `json:"dids"`
}

type BatchDIDRouter struct {
	service *did.BatchService
}

func NewBatchDIDRouter(svc *did.BatchService) *BatchDIDRouter {
	return &BatchDIDRouter{service: svc}
}

// BatchCreateDIDs godoc
//
//	@Summary		Batch Create DIDs
//	@Description	Create a batch of DIDs. The operation is atomic, meaning that all requests will
//	@Description	succeed or fail. This is currently only supported for the DID method named `did:key`.
//	@Tags			DecentralizedIdentifiers
//	@Accept			json
//	@Produce		json
//	@Param			method	path		string					true	"Method. Only `key` is supported."
//	@Param			request	body		BatchCreateDIDsRequest	true	"The batch requests"
//	@Success		201		{object}	BatchCreateDIDsResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/dids/{method}/batch [put]
func (dr BatchDIDRouter) BatchCreateDIDs(c *gin.Context) {
	method := framework.GetParam(c, MethodParam)
	if method == nil {
		errMsg := "create DID request missing method parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	if *method != "key" {
		errMsg := "create DID request method parameter must be `key`"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}
	invalidCreateDIDRequest := "invalid batch create DID request"
	var batchRequest BatchCreateDIDsRequest
	if err := framework.Decode(c.Request, &batchRequest); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateDIDRequest, http.StatusBadRequest)
		return
	}

	batchCreateMaxItems := dr.service.Config().BatchCreateMaxItems
	if len(batchRequest.Requests) > batchCreateMaxItems {
		framework.LoggingRespondErrMsg(c, fmt.Sprintf("max number of requests is %d", batchCreateMaxItems), http.StatusBadRequest)
		return
	}

	req, err := batchRequest.toServiceRequest(didsdk.Method(*method))
	if err != nil {
		framework.LoggingRespondError(c, err, http.StatusBadRequest)
		return
	}
	batchCreateDIDsResponse, err := dr.service.BatchCreateDIDs(c, *req)
	if err != nil {
		errMsg := "could not create credentials"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	var resp BatchCreateDIDsResponse
	resp.DIDs = append(resp.DIDs, batchCreateDIDsResponse.DIDs...)

	framework.Respond(c, resp, http.StatusCreated)
}
