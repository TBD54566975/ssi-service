package schema

import "github.com/TBD54566975/ssi-sdk/credential/schema"

const (
	// VCJSONSchemaType https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition_metadata
	VCJSONSchemaType string = "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json"
	Version1         string = "1.0.0"
)

type GetSchemasResponse struct {
	Schemas []schema.VCJSONSchema `json:"schemas,omitempty"`
}

type CreateSchemaRequest struct {
	Author string            `json:"author" validate:"required"`
	Name   string            `json:"name" validate:"required"`
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
