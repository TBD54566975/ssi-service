package schema

import "github.com/TBD54566975/ssi-sdk/credential/schema"

type GetAllSchemasResponse struct {
	Schemas []schema.VCJSONSchema `json:"schemas,omitempty"`
}

type CreateSchemaRequest struct {
	DID    string            `json:"did" validate:"required"`
	Schema schema.JSONSchema `json:"schema" validate:"required"`
}

type CreateSchemaResponse struct {
	ID     string              `json:"id"`
	Schema schema.VCJSONSchema `json:"schema"`
}

type GetSchemaByIDRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetSchemaByIDResponse struct {
	Schema schema.VCJSONSchema `json:"schema"`
}
