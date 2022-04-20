package router

import (
	"context"
	"fmt"
	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/server/framework"
	svcframework "github.com/tbd54566975/ssi-service/pkg/service/framework"
	"github.com/tbd54566975/ssi-service/pkg/service/schema"
	"log"
	"net/http"
)

type SchemaRouter struct {
	service *schema.Service
	logger  *log.Logger
}

func NewSchemaRouter(s svcframework.Service, l *log.Logger) (*SchemaRouter, error) {
	if s == nil {
		return nil, errors.New("service cannot be nil")
	}
	schemaService, ok := s.(*schema.Service)
	if !ok {
		return nil, fmt.Errorf("could not create schema router with service type: %s", s.Type())
	}
	return &SchemaRouter{
		service: schemaService,
		logger:  l,
	}, nil
}

type CreateSchemaRequest struct {
	Author string               `json:"author" validate:"required"`
	Name   string               `json:"name" validate:"required"`
	Schema schemalib.JSONSchema `json:"schema" validate:"required"`
}

type CreateSchemaResponse struct {
	ID     string                 `json:"id"`
	Schema schemalib.VCJSONSchema `json:"schema"`
}

func (sr SchemaRouter) CreateSchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request CreateSchemaRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid create schema request"
		sr.logger.Printf(errors.Wrap(err, errMsg).Error())
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	req := schema.CreateSchemaRequest{Author: request.Author, Name: request.Name, Schema: request.Schema}
	createSchemaResponse, err := sr.service.CreateSchema(req)
	if err != nil {
		errMsg := fmt.Sprintf("could not create schema with authoring DID: %s", request.Author)
		sr.logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusInternalServerError)
	}

	resp := CreateSchemaResponse{ID: createSchemaResponse.ID, Schema: createSchemaResponse.Schema}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

type GetSchemasResponse struct {
	Schemas []schemalib.VCJSONSchema `json:"schemas,omitempty"`
}

func (sr SchemaRouter) GetSchemas(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	gotSchemas, err := sr.service.GetSchemas()
	if err != nil {
		errMsg := "could not get schemas"
		sr.logger.Printf(errors.Wrap(err, errMsg).Error())
		return framework.NewRequestErrorMsg(errMsg, http.StatusInternalServerError)
	}
	resp := GetSchemasResponse{Schemas: gotSchemas.Schemas}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetSchemaResponse struct {
	Schema schemalib.VCJSONSchema `json:"schema,omitempty"`
}

func (sr SchemaRouter) GetSchemaByID(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get schema without ID parameter"
		sr.logger.Printf(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) differentiate between internal errors and not found schemas
	gotSchema, err := sr.service.GetSchemaByID(schema.GetSchemaByIDRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get schema with id: %s", *id)
		sr.logger.Printf(errors.Wrap(err, errMsg).Error())
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	resp := GetSchemaResponse{Schema: gotSchema.Schema}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}
