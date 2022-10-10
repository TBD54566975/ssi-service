package router

import (
	"context"
	"fmt"
	"net/http"

	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
)

type SchemaRouter struct {
	service *schema.Service
}

func NewSchemaRouter(s svcframework.Service) (*SchemaRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	schemaService, ok := s.(*schema.Service)
	if !ok {
		return nil, fmt.Errorf("could not create schema router with service type: %s", s.Type())
	}
	return &SchemaRouter{
		service: schemaService,
	}, nil
}

type CreateSchemaRequest struct {
	Author string               `json:"author" validate:"required"`
	Name   string               `json:"name" validate:"required"`
	Schema schemalib.JSONSchema `json:"schema" validate:"required"`
}

type CreateSchemaResponse struct {
	ID        string                 `json:"id"`
	Schema    schemalib.VCJSONSchema `json:"schema"`
	SchemaJWT string                 `json:"schemaJwt"`
}

// CreateSchema godoc
// @Summary      Create Schema
// @Description  Create schema
// @Tags         SchemaAPI
// @Accept       json
// @Produce      json
// @Param        request  body      CreateSchemaRequest  true  "request body"
// @Success      201      {object}  CreateSchemaResponse
// @Failure      400      {string}  string  "Bad request"
// @Failure      500      {string}  string  "Internal server error"
// @Router       /v1/schemas [put]
func (sr SchemaRouter) CreateSchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateSchemaRequest
	invalidCreateSchemaRequest := "invalid create schema request"
	if err := framework.Decode(r, &request); err != nil {
		errMsg := invalidCreateSchemaRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		errMsg := invalidCreateSchemaRequest
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	req := schema.CreateSchemaRequest{Author: request.Author, Name: request.Name, Schema: request.Schema}
	createSchemaResponse, err := sr.service.CreateSchema(req)
	if err != nil {
		errMsg := fmt.Sprintf("could not create schema with authoring DID: %s", request.Author)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateSchemaResponse{ID: createSchemaResponse.ID, Schema: createSchemaResponse.Schema}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetSchemasResponse struct {
	Schemas []schemalib.VCJSONSchema `json:"schemas,omitempty"`
}

// GetSchemas godoc
// @Summary      Get Schemas
// @Description  Get schemas
// @Tags         SchemaAPI
// @Accept       json
// @Produce      json
// @Success      200  {object}  GetSchemasResponse
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/schemas [get]
func (sr SchemaRouter) GetSchemas(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	gotSchemas, err := sr.service.GetSchemas()
	if err != nil {
		errMsg := "could not get schemas"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}
	resp := GetSchemasResponse{Schemas: gotSchemas.Schemas}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetSchemaResponse struct {
	Schema schemalib.VCJSONSchema `json:"schema,omitempty"`
}

// GetSchema godoc
// @Summary      Get Schema
// @Description  Get a schema by its ID
// @Tags         SchemaAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {object}  GetSchemaResponse
// @Failure      400  {string}  string  "Bad request"
// @Router       /v1/schemas/{id} [get]
func (sr SchemaRouter) GetSchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get schema without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) differentiate between internal errors and not found schemas
	gotSchema, err := sr.service.GetSchema(schema.GetSchemaRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get schema with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetSchemaResponse{Schema: gotSchema.Schema}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteSchema godoc
// @Summary      Delete Schema
// @Description  Delete a schema by its ID
// @Tags         SchemaAPI
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "ID"
// @Success      200  {string}  string  "OK"
// @Failure      400  {string}  string  "Bad request"
// @Failure      500  {string}  string  "Internal server error"
// @Router       /v1/schemas/{id} [delete]
func (sr SchemaRouter) DeleteSchema(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete a schema without an ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := sr.service.DeleteSchema(schema.DeleteSchemaRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete schema with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
