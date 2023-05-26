package schema

import (
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/TBD54566975/ssi-sdk/util"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

type CreateSchemaRequest struct {
	Name        string            `json:"name" validate:"required"`
	Description string            `json:"description,omitempty"`
	Schema      schema.JSONSchema `json:"schema" validate:"required"`

	// If sign == true, the schema will be signed by the author's private key with the specified KID
	Sign      bool   `json:"sign,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	IssuerKID string `json:"issuerKid,omitempty"`
}

func (csr CreateSchemaRequest) IsValid() bool {
	return util.IsValidStruct(csr) == nil
}

type CreateSchemaResponse struct {
	ID               string            `json:"id"`
	Schema           schema.JSONSchema `json:"schema"`
	CredentialSchema *keyaccess.JWT    `json:"credentialSchema,omitempty"`
}

type ListSchemasResponse struct {
	Schemas []GetSchemaResponse `json:"schemas,omitempty"`
}

type GetSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetSchemaResponse struct {
	ID               string            `json:"id"`
	Schema           schema.JSONSchema `json:"schema"`
	CredentialSchema *keyaccess.JWT    `json:"credentialSchema,omitempty"`
}

type DeleteSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}
