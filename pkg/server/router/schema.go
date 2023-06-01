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
	// Name is a human-readable name for a schema
	Name string `json:"name" validate:"required"`
	// Description is an optional human-readable description for a schema
	Description string `json:"description,omitempty"`
	// Schema represents the JSON schema for the credential schema
	// If the schema has an $id field, it will be overwritten with an ID the service generates.
	// The schema must be against draft 2020-12, 2019-09, or 7.
	Schema schemalib.JSONSchema `json:"schema" validate:"required"`

	// Issuer represents the DID of the issuer for the schema if it's signed. Required if intending to sign the
	// schema as a credential using CredentialSchema2023.
	Issuer string `json:"issuer,omitempty"`
	// IssuerKID represents the KID of the issuer's private key to sign the schema. Required if intending to sign the
	// schema as a credential using CredentialSchema2023.
	IssuerKID string `json:"issuerKid,omitempty"`
}

type CreateSchemaResponse struct {
	ID   string                     `json:"id"`
	Type schemalib.VCJSONSchemaType `json:"type" validate:"required"`

	// Schema is the JSON schema for the credential, returned when the type is JsonSchema2023
	Schema *schemalib.JSONSchema `json:"schema,omitempty"`

	// CredentialSchema is the JWT schema for the credential, returned when the type is CredentialSchema2023
	CredentialSchema *keyaccess.JWT `json:"credentialSchema,omitempty"`
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
func (sr SchemaRouter) CreateSchema(c *gin.Context) {
	var request CreateSchemaRequest
	invalidCreateSchemaRequest := "invalid create schema request"
	if err := framework.Decode(c.Request, &request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateSchemaRequest, http.StatusBadRequest)
		return
	}

	if err := framework.ValidateRequest(request); err != nil {
		framework.LoggingRespondErrWithMsg(c, err, invalidCreateSchemaRequest, http.StatusBadRequest)
		return
	}

	if (request.Issuer == "" && request.IssuerKID != "") || (request.Issuer != "" && request.IssuerKID == "") {
		errMsg := "cannot sign schema without an issuer DID and KID"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	req := schema.CreateSchemaRequest{
		Name:        request.Name,
		Description: request.Description,
		Schema:      request.Schema,
		Issuer:      request.Issuer,
		IssuerKID:   request.IssuerKID,
	}
	createSchemaResponse, err := sr.service.CreateSchema(c, req)
	if err != nil {
		framework.LoggingRespondErrWithMsg(c, err, "could not create schema", http.StatusInternalServerError)
		return
	}

	resp := CreateSchemaResponse{
		ID:               createSchemaResponse.ID,
		Type:             createSchemaResponse.Type,
		Schema:           createSchemaResponse.Schema,
		CredentialSchema: createSchemaResponse.CredentialSchema,
	}
	framework.Respond(c, resp, http.StatusCreated)
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
func (sr SchemaRouter) GetSchema(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot get schema without ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	// TODO(gabe) differentiate between internal errors and not found schemas
	gotSchema, err := sr.service.GetSchema(c, schema.GetSchemaRequest{ID: *id})
	if err != nil {
		errMsg := fmt.Sprintf("could not get schema with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	resp := GetSchemaResponse{Schema: gotSchema.Schema}
	framework.Respond(c, resp, http.StatusOK)
	return
}

type ListSchemasResponse struct {
	Schemas []GetSchemaResponse `json:"schemas,omitempty"`
}

// ListSchemas godoc
//
//	@Summary		List Schemas
//	@Description	List schemas
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListSchemasResponse
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/schemas [get]
func (sr SchemaRouter) ListSchemas(c *gin.Context) {
	gotSchemas, err := sr.service.ListSchemas(c)
	if err != nil {
		errMsg := "could not list schemas"
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	schemas := make([]GetSchemaResponse, 0, len(gotSchemas.Schemas))
	for _, s := range gotSchemas.Schemas {
		schemas = append(schemas, GetSchemaResponse{Schema: s.Schema})
	}

	resp := ListSchemasResponse{Schemas: schemas}
	framework.Respond(c, resp, http.StatusOK)
}

type GetSchemaResponse struct {
	ID   string                     `json:"id" validate:"required"`
	Type schemalib.VCJSONSchemaType `json:"type" validate:"required"`

	// Schema is the JSON schema for the credential, returned when the type is JsonSchema2023
	Schema *schemalib.JSONSchema `json:"schema,omitempty"`

	// CredentialSchema is the JWT schema for the credential, returned when the type is CredentialSchema2023
	CredentialSchema *keyaccess.JWT `json:"credentialSchema,omitempty"`
}

// DeleteSchema godoc
//
//	@Summary		Delete Schema
//	@Description	Delete a schema by its ID
//	@Tags			SchemaAPI
//	@Accept			json
//	@Produce		json
//	@Param			id	path		string	true	"ID"
//	@Success		204	{string}	string	"No Content"
//	@Failure		400	{string}	string	"Bad request"
//	@Failure		500	{string}	string	"Internal server error"
//	@Router			/v1/schemas/{id} [delete]
func (sr SchemaRouter) DeleteSchema(c *gin.Context) {
	id := framework.GetParam(c, IDParam)
	if id == nil {
		errMsg := "cannot delete a schema without an ID parameter"
		framework.LoggingRespondErrMsg(c, errMsg, http.StatusBadRequest)
		return
	}

	if err := sr.service.DeleteSchema(c, schema.DeleteSchemaRequest{ID: *id}); err != nil {
		errMsg := fmt.Sprintf("could not delete schema with id: %s", *id)
		framework.LoggingRespondErrWithMsg(c, err, errMsg, http.StatusInternalServerError)
		return
	}

	framework.Respond(c, nil, http.StatusNoContent)
}
