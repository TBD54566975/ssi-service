package schema

import "github.com/TBD54566975/ssi-sdk/credential/schema"

const (
	Version1 string = "1.0.0"
)

type CreateSchemaRequest struct {
	Author string            `json:"author" validate:"required"`
	Name   string            `json:"name" validate:"required"`
	Schema schema.JSONSchema `json:"schema" validate:"required"`
}

type CreateSchemaResponse struct {
	ID     string              `json:"id"`
	Schema schema.VCJSONSchema `json:"schema"`
}

type GetSchemasResponse struct {
	Schemas []schema.VCJSONSchema `json:"schemas,omitempty"`
}

type GetSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetSchemaResponse struct {
	Schema schema.VCJSONSchema `json:"schema"`
}
