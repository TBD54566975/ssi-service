package router

import (
	"fmt"
	"net/http"

	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.einride.tech/aip/filtering"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	manifestsvc "github.com/tbd54566975/ssi-service/pkg/service/manifest/model"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
)

type OperationRouter struct {
	service *operation.Service
}

func NewOperationRouter(s svcframework.Service) (*OperationRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	service, ok := s.(*operation.Service)
	if !ok {
		return nil, fmt.Errorf("casting service: %s", s.Type())
	}
	return &OperationRouter{service: service}, nil
}

// GetOperation godoc
//
// @Summary     Get an operation
// @Description Get operation by its ID
// @Tags        OperationAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string    true "ID"
// @Success     200 {object} Operation "OK"
// @Failure     400 {string} string    "Bad request"
// @Failure     500 {string} string    "Internal server error"
// @Router      /v1/operations/{id} [get]
func (o OperationRouter) GetOperation(ctx *gin.Context) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		return framework.NewRequestError(
			sdkutil.LoggingNewError("get operation request requires id"), http.StatusBadRequest)
	}

	op, err := o.service.GetOperation(ctx, operation.GetOperationRequest{ID: *id})
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "failed getting operation"), http.StatusInternalServerError)
	}
	return framework.Respond(ctx, routerModel(*op), http.StatusOK)
}

type GetOperationsRequest struct {
	// The name of the parent's resource. For example: "/presentation/submissions".
	Parent string `json:"parent"`

	// A standard filter expression conforming to https://google.aip.dev/160.
	// For example: `done = true`.
	Filter string `json:"filter"`
}

func (r GetOperationsRequest) GetFilter() string {
	return r.Filter
}

const (
	DoneIdentifier = "done"
	True           = "true"
	False          = "false"
)

const FilterCharacterLimit = 1024

func (r GetOperationsRequest) ToServiceRequest() (operation.GetOperationsRequest, error) {
	var opReq operation.GetOperationsRequest
	opReq.Parent = r.Parent

	declarations, err := filtering.NewDeclarations(
		filtering.DeclareFunction(filtering.FunctionEquals,
			filtering.NewFunctionOverload(
				filtering.FunctionOverloadEqualsString, filtering.TypeBool, filtering.TypeBool, filtering.TypeBool)),
		filtering.DeclareIdent(DoneIdentifier, filtering.TypeBool),
		filtering.DeclareIdent(True, filtering.TypeBool),
		filtering.DeclareIdent(False, filtering.TypeBool),
	)
	if err != nil {
		return opReq, errors.Wrap(err, "creating new filter declarations")
	}

	// Because parsing filters can be expensive, we limit is to a fixed len of chars. That should be more than enough
	// for most use cases.
	if len(r.GetFilter()) > FilterCharacterLimit {
		return opReq, errors.Errorf("filter longer than %d character size limit", FilterCharacterLimit)
	}
	filter, err := filtering.ParseFilter(r, declarations)
	if err != nil {
		return opReq, errors.Wrap(err, "parsing filter")
	}
	opReq.Filter = filter
	return opReq, nil
}

type GetOperationsResponse struct {
	Operations []Operation `json:"operations"`
}

// GetOperations godoc
//
// @Summary     List operations
// @Description List operations according to the request
// @Tags        OperationAPI
// @Accept      json
// @Produce     json
// @Param       request body     GetOperationsRequest  true "request body"
// @Success     200     {object} GetOperationsResponse "OK"
// @Failure     400     {string} string                "Bad request"
// @Failure     500     {string} string                "Internal server error"
// @Router      /v1/operations [get]
func (o OperationRouter) GetOperations(ctx *gin.Context) error {
	var request GetOperationsRequest
	if err := framework.Decode(ctx.Request, &request); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid get operations request"), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid get operations request"), http.StatusBadRequest)
	}

	req, err := request.ToServiceRequest()
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "invalid get operations request"), http.StatusBadRequest)
	}

	ops, err := o.service.GetOperations(ctx, req)
	if err != nil {
		logrus.WithError(err).Error("getting operations from service")
		return framework.NewRequestError(err, http.StatusInternalServerError)
	}
	resp := GetOperationsResponse{Operations: make([]Operation, 0, len(ops.Operations))}
	for _, op := range ops.Operations {
		resp.Operations = append(resp.Operations, routerModel(op))
	}
	return framework.Respond(ctx, resp, http.StatusOK)
}

func routerModel(op operation.Operation) Operation {
	routerOp := Operation{
		ID:   op.ID,
		Done: op.Done,
		Result: OperationResult{
			Error: op.Result.Error,
		},
	}
	if op.Result.Response != nil {
		switch r := op.Result.Response.(type) {
		case manifestsvc.SubmitApplicationResponse:
			routerOp.Result.Response = SubmitApplicationResponse{
				Response:    r.Response,
				Credentials: r.Credentials,
				ResponseJWT: r.ResponseJWT,
			}
		default:
			routerOp.Result.Response = r
		}
	}
	return routerOp
}

// CancelOperation godoc
//
// @Summary     Cancel an ongoing operation
// @Description Cancels an ongoing operation, if possible.
// @Tags        OperationAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string    true "ID"
// @Success     200 {object} Operation "OK"
// @Failure     400 {string} string    "Bad request"
// @Failure     500 {string} string    "Internal server error"
// @Router      /v1/operations/cancel/{id} [get]
func (o OperationRouter) CancelOperation(ctx *gin.Context) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		return framework.NewRequestError(
			sdkutil.LoggingNewError("get operation request requires id"), http.StatusBadRequest)
	}

	op, err := o.service.CancelOperation(ctx, operation.CancelOperationRequest{ID: *id})
	if err != nil {
		return framework.NewRequestError(
			sdkutil.LoggingErrorMsg(err, "failed cancelling operation"), http.StatusInternalServerError)
	}
	return framework.Respond(ctx, routerModel(*op), http.StatusOK)
}

type Operation struct {
	// The name of the resource related to this operation. E.g. "presentations/submissions/<uuid>"
	ID string `json:"id"`

	// Whether this operation has finished.
	Done bool `json:"done"`

	// Populated if Done == true.
	Result OperationResult `json:"result,omitempty"`
}

type OperationResult struct {
	// Populated when there was an error with the operation.
	Error string `json:"error,omitempty"`

	// Populated iff Error == "". The type should be specified in the calling APIs documentation.
	Response any `json:"response,omitempty"`
}
