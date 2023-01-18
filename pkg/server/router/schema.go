package router

import (
	"context"
	"fmt"
	"net/http"

	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
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
	return &SchemaRouter{service: schemaService}, nil
}

type CreateSchemaRequest struct {
	Author string               `json:"author" validate:"required"`
	Name   string               `json:"name" validate:"required"`
	Schema schemalib.JSONSchema `json:"schema" validate:"required"`
	// Sign represents whether the schema should be signed by the author. Default is false.
	Sign bool `json:"sign"`
}

type CreateSchemaResponse struct {
	ID        string                 `json:"id"`
	Schema    schemalib.VCJSONSchema `json:"schema"`
	SchemaJWT *keyaccess.JWT         `json:"schemaJwt,omitempty"`
}

// CreateSchema godoc
//
//	@Summary		Create Schema
//	@Description	Create schema
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		CreateSchemaRequest	true	"request body"
//	@Success		201		{object}	CreateSchemaResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Failure		500		{string}	string	"Internal server error"
//	@Router			/v1/schemas [put]
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

	req := schema.CreateSchemaRequest{Author: request.Author, Name: request.Name, Schema: request.Schema, Sign: request.Sign}
	createSchemaResponse, err := sr.service.CreateSchema(ctx, req)
	if err != nil {
		errMsg := fmt.Sprintf("could not create schema with authoring DID: %s", request.Author)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := CreateSchemaResponse{ID: createSchemaResponse.ID, Schema: createSchemaResponse.Schema, SchemaJWT: createSchemaResponse.SchemaJWT}
	return framework.Respond(ctx, w, resp, http.StatusCreated)
}

// GetSchema godoc
//
//	@Summary		Get Schema
//	@Description	Get a schema by its ID
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{object}	GetSchemaResponse
//	@Failure		400	{string}	string	"Bad request"
//	@Router			/v1/schemas/{id} [get]
func (sr SchemaRouter) GetSchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot get schema without ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) differentiate between internal errors and not found schemas
	gotSchema, err := sr.service.GetSchema(ctx, schema.GetSchemaRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get schema with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	resp := GetSchemaResponse{Schema: gotSchema.Schema, SchemaJWT: gotSchema.SchemaJWT}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetSchemasResponse struct {
	Schemas []GetSchemaResponse `json:"schemas,omitempty"`
}

// GetSchemas godoc
//
//	@Summary		Get Schemas
//	@Description	Get schemas
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetSchemasResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/schemas [get]
func (sr SchemaRouter) GetSchemas(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	gotSchemas, err := sr.service.GetSchemas(ctx)
	if err != nil {
		errMsg := "could not get schemas"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	schemas := make([]GetSchemaResponse, 0, len(gotSchemas.Schemas))
	for _, s := range gotSchemas.Schemas {
		schemas = append(schemas, GetSchemaResponse{Schema: s.Schema})
	}

	resp := GetSchemasResponse{Schemas: schemas}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

type GetSchemaResponse struct {
	Schema    schemalib.VCJSONSchema `json:"schema,omitempty"`
	SchemaJWT *keyaccess.JWT         `json:"schemaJwt,omitempty"`
}

type VerifySchemaRequest struct {
	SchemaJWT keyaccess.JWT `json:"schemaJwt" validate:"required"`
}

type VerifySchemaResponse struct {
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`
}

// VerifySchema godoc
//
//	@Summary		Verify Schema
//	@Description	Verify a given schema by its id
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Param			request	body		VerifySchemaRequest	true	"request body"
//	@Success		200		{object}	VerifySchemaResponse
//	@Failure		400		{string}	string	"Bad request"
//	@Router			/v1/schemas/verification [put]
func (sr SchemaRouter) VerifySchema(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var request VerifySchemaRequest
	if err := framework.Decode(r, &request); err != nil {
		errMsg := "invalid verify schema request"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusBadRequest)
	}

	verificationResult, err := sr.service.VerifySchema(schema.VerifySchemaRequest{SchemaJWT: request.SchemaJWT})
	if err != nil {
		errMsg := "could not verify schema"
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	resp := VerifySchemaResponse{Verified: verificationResult.Verified, Reason: verificationResult.Reason}
	return framework.Respond(ctx, w, resp, http.StatusOK)
}

// DeleteSchema godoc
//
//	@Summary		Delete Schema
//	@Description	Delete a schema by its ID
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		200	{string}	string	"OK"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/schemas/{id} [delete]
func (sr SchemaRouter) DeleteSchema(ctx context.Context, w http.ResponseWriter, _ *http.Request) error {
	id := framework.GetParam(ctx, IDParam)
	if id == nil {
		errMsg := "cannot delete a schema without an ID parameter"
		logrus.Error(errMsg)
		return framework.NewRequestErrorMsg(errMsg, http.StatusBadRequest)
	}

	if err := sr.service.DeleteSchema(ctx, schema.DeleteSchemaRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete schema with id: %s", *id)
		logrus.WithError(err).Error(errMsg)
		return framework.NewRequestError(errors.Wrap(err, errMsg), http.StatusInternalServerError)
	}

	return framework.Respond(ctx, w, nil, http.StatusOK)
}
