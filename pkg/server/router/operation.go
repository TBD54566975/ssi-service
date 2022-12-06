package router

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/operation"
	"go.einride.tech/aip/filtering"
	"net/http"
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
// @Summary      Get an operation
// @Description  Get operation by its ID
// @Tags         OperationAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  Operation  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/operations/{id} [get]
func (pdr OperationRouter) GetOperation(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
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
// @Summary      List operations
// @Description  List operations according to the request
// @Tags         OperationAPI
// @Accept       json
// @Produce      json
// @Param        request  body  GetOperationsRequest  true  "request body"
// @Success      200  {object}  GetOperationsResponse  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/operations [get]
func (pdr OperationRouter) GetOperations(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request GetOperationsRequest
	if err := framework.Decode(r, &request); err != nil {
		return framework.NewRequestError(
			util.LoggingErrorMsg(err, "invalid get operations request"), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		return framework.NewRequestError(
			util.LoggingErrorMsg(err, "invalid get operations request"), http.StatusBadRequest)
	}

	req, err := request.ToServiceRequest()
	if err != nil {
		return framework.NewRequestError(
			util.LoggingErrorMsg(err, "invalid get operations request"), http.StatusBadRequest)
	}

	ops, err := pdr.service.GetOperations(req)
	if err != nil {
		logrus.WithError(err).Error("getting operations from service")
		return framework.NewRequestError(err, http.StatusInternalServerError)
	}
	resp := GetOperationsResponse{Operations: make([]Operation, len(ops.Operations))}
	for i, op := range ops.Operations {
		resp.Operations[i].ID = op.ID
		resp.Operations[i].Done = op.Done
		resp.Operations[i].Result.Error = op.Result.Error
		resp.Operations[i].Result.Response = op.Result.Response
	}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// CancelOperation godoc
// @Summary      Cancel an ongoing operation
// @Description  Cancels an ongoing operation, if possible.
// @Tags         OperationAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetOperationsResponse  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/operations [get]
func (pdr OperationRouter) CancelOperation(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
}
