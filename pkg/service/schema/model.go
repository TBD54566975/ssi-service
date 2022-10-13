package schema

import (
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/util"
)

const (
	Version1 string = "1.0"
)

type CreateSchemaRequest struct {
	Author string            `json:"author" validate:"required"`
	Name   string            `json:"name" validate:"required"`
	Schema schema.JSONSchema `json:"schema" validate:"required"`
	Sign   bool              `json:"signed"`
}

func (csr CreateSchemaRequest) IsValid() bool {
	return util.IsValidStruct(csr) == nil
}

type CreateSchemaResponse struct {
	ID        string              `json:"id"`
	Schema    schema.VCJSONSchema `json:"schema"`
	SchemaJWT *string             `json:"schemaJwt,omitempty"`
}

type GetSchemasResponse struct {
	Schemas []GetSchemaResponse `json:"schemas,omitempty"`
}

type GetSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetSchemaResponse struct {
	ID        string              `json:"id"`
	Schema    schema.VCJSONSchema `json:"schema"`
	SchemaJWT *string             `json:"schemaJwt,omitempty"`
}

type DeleteSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}
