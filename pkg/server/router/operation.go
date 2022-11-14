package router

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
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

type Operation struct {
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
	Parent string `json:"parent"`
	Filter string `json:"filter"`
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
// @Param        request  body      GetOperationsRequest  true  "request body"
// @Success      200  {object}  GetOperationsResponse  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/operations [get]
func (pdr OperationRouter) GetOperations(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	return nil
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
