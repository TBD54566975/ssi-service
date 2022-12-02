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
	// For example: 'status = done'.
	Filter string `json:"filter"`
}

func (r GetOperationsRequest) ToServiceRequest() operation.GetOperationsRequest {
	return operation.GetOperationsRequest{
		Parent: r.Parent,
		Filter: r.Filter,
	}
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

	req := request.ToServiceRequest()

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
