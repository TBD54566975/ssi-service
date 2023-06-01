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

	// If both are present the schema will be signed by the issuer's private key with the specified KID
	Issuer    string `json:"issuer,omitempty"`
	IssuerKID string `json:"issuerKid,omitempty"`
}

// IsCredentialSchemaRequest returns true if the request is for a credential schema
func (csr CreateSchemaRequest) IsCredentialSchemaRequest() bool {
	return csr.Issuer != "" && csr.IssuerKID != ""
}

func (csr CreateSchemaRequest) IsValid() bool {
	return util.IsValidStruct(csr) == nil
}

type CreateSchemaResponse struct {
	ID               string                  `json:"id"`
	Type             schema.VCJSONSchemaType `json:"type"`
	Schema           *schema.JSONSchema      `json:"schema,omitempty"`
	CredentialSchema *keyaccess.JWT          `json:"credentialSchema,omitempty"`
}

type ListSchemasResponse struct {
	Schemas []GetSchemaResponse `json:"schemas,omitempty"`
}

type GetSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetSchemaResponse struct {
	ID               string                  `json:"id"`
	Type             schema.VCJSONSchemaType `json:"type"`
	Schema           *schema.JSONSchema      `json:"schema,omitempty"`
	CredentialSchema *keyaccess.JWT          `json:"credentialSchema,omitempty"`
}

type DeleteSchemaRequest struct {
	ID string `json:"id" validate:"required"`
}
