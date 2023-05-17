package router

import (
	"fmt"
	"net/http"

	schemalib "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

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
	// If sign is true, the schema will be signed by the author's private key with the specified KID
	Sign bool `json:"sign"`
	// AuthorKID represents the KID of the author's private key to sign the schema. Required if sign is true.
	AuthorKID string `json:"authorKid"`
}

type CreateSchemaResponse struct {
	ID        string                 `json:"id"`
	Schema    schemalib.VCJSONSchema `json:"schema"`
	SchemaJWT *keyaccess.JWT         `json:"schemaJwt,omitempty"`
}

// CreateSchema godoc
//
// @Summary     Create SchemaID
// @Description Create schema
// @Tags        SchemaAPI
// @Accept      json
// @Produce     json
// @Param       request body     CreateSchemaRequest true "request body"
// @Success     201     {object} CreateSchemaResponse
// @Failure     400     {string} string "Bad request"
// @Failure     500     {string} string "Internal server error"
// @Router      /v1/schemas [put]
func (sr SchemaRouter) CreateSchema(c *gin.Context) error {
	var request CreateSchemaRequest
	invalidCreateSchemaRequest := "invalid create schema request"
	if err := framework.Decode(c.Request, &request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateSchemaRequest, http.StatusBadRequest)
	}

	if err := framework.ValidateRequest(request); err != nil {
		return framework.LoggingRespondErrWithMsg(c, err, invalidCreateSchemaRequest, http.StatusBadRequest)
	}

	if request.Sign && request.AuthorKID == "" {
		errMsg := "cannot sign schema without authorKID"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	req := schema.CreateSchemaRequest{Author: request.Author, AuthorKID: request.AuthorKID, Name: request.Name, Schema: request.Schema, Sign: request.Sign}
	createSchemaResponse, err := sr.service.CreateSchema(c, req)
	if err != nil {
		errMsg := fmt.Sprintf("could not create schema with authoring DID<%s> and KID<%s>", request.Author, request.AuthorKID)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := CreateSchemaResponse{ID: createSchemaResponse.ID, Schema: createSchemaResponse.Schema, SchemaJWT: createSchemaResponse.SchemaJWT}
	return framework.Respond(c, resp, http.StatusCreated)
}

// GetSchema godoc
//
// @Summary     Get SchemaID
// @Description Get a schema by its ID
// @Tags        SchemaAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     200 {object} GetSchemaResponse
// @Failure     400 {string} string "Bad request"
// @Router      /v1/schemas/{id} [get]
func (sr SchemaRouter) GetSchema(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get schema without ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	// TODO(gabe) differentiate between internal errors and not found schemas
	gotSchema, err := sr.service.GetSchema(c, schema.GetSchemaRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get schema with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := GetSchemaResponse{Schema: gotSchema.Schema, SchemaJWT: gotSchema.SchemaJWT}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetSchemasResponse struct {
	Schemas []GetSchemaResponse `json:"schemas,omitempty"`
}

// GetSchemas godoc
//
// @Summary     Get Schemas
// @Description Get schemas
// @Tags        SchemaAPI
// @Accept      json
// @Produce     json
// @Success     200 {object} GetSchemasResponse
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/schemas [get]
func (sr SchemaRouter) GetSchemas(c *gin.Context) error {
	gotSchemas, err := sr.service.GetSchemas(c)
	if err != nil {
		errMsg := "could not get schemas"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	schemas := make([]GetSchemaResponse, 0, len(gotSchemas.Schemas))
	for _, s := range gotSchemas.Schemas {
		schemas = append(schemas, GetSchemaResponse{Schema: s.Schema})
	}

	resp := GetSchemasResponse{Schemas: schemas}
	return framework.Respond(c, resp, http.StatusOK)
}

type GetSchemaResponse struct {
	Schema    schemalib.VCJSONSchema `json:"schema,omitempty"`
	SchemaJWT *keyaccess.JWT         `json:"schemaJwt,omitempty"`
}

type VerifySchemaRequest struct {
	SchemaJWT keyaccess.JWT `json:"schemaJwt" validate:"required"`
}

type VerifySchemaResponse struct {
	Verified bool   `json:"verified,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// VerifySchema godoc
//
// @Summary     Verify SchemaID
// @Description Verify a given schema by its id
// @Tags        SchemaAPI
// @Accept      json
// @Produce     json
// @Param       request body     VerifySchemaRequest true "request body"
// @Success     200     {object} VerifySchemaResponse
// @Failure     400     {string} string "Bad request"
// @Router      /v1/schemas/verification [put]
func (sr SchemaRouter) VerifySchema(c *gin.Context) error {
	var request VerifySchemaRequest
	if err := framework.Decode(c.Request, &request); err != nil {
		errMsg := "invalid verify schema request"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusBadRequest)
	}

	verificationResult, err := sr.service.VerifySchema(c, schema.VerifySchemaRequest{SchemaJWT: request.SchemaJWT})
	if err != nil {
		errMsg := "could not verify schema"
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	resp := VerifySchemaResponse{Verified: verificationResult.Verified, Reason: verificationResult.Reason}
	return framework.Respond(c, resp, http.StatusOK)
}

// DeleteSchema godoc
//
// @Summary     Delete SchemaID
// @Description Delete a schema by its ID
// @Tags        SchemaAPI
// @Accept      json
// @Produce     json
// @Param       id  path     string true "ID"
// @Success     204 {string} string "No Content"
// @Failure     400 {string} string "Bad request"
// @Failure     500 {string} string "Internal server error"
// @Router      /v1/schemas/{id} [delete]
func (sr SchemaRouter) DeleteSchema(c *gin.Context) error {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete a schema without an ID parameter"
		return framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
	}

	if err := sr.service.DeleteSchema(c, schema.DeleteSchemaRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete schema with id: %s", *id)
		return framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
	}

	return framework.Respond(c, nil, http.StatusNoContent)
}
