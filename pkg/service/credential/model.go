package credential

import (
	"github.com/tbd54566975/ssi-service/internal/credential"
)

const (
	SchemaLDType string = "JsonSchemaValidator2018"
)

type CreateCredentialRequest struct {
	Issuer  string `json:"issuer" validate:"required"`
	Subject string `json:"subject" validate:"required"`
	// A context is optional. If not present, we'll apply default, required context values.
	Context string `json:"context,omitempty"`
	// A schema is optional. If present, we'll attempt to look it up and validate the data against it.
	JSONSchema string                 `json:"jsonSchema,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Expiry     string                 `json:"expiry,omitempty"`
	// TODO(gabe) support more capabilities like signature type, format, status, and more.
}

// CreateCredentialResponse holds a resulting credential from credential creation, which is an XOR type:
// containing either a Data Integrity Proofed credential or a VC-JWT representation.
type CreateCredentialResponse struct {
	credential.Container `json:"credential,omitempty"`
}

type GetCredentialRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetCredentialResponse struct {
	credential.Container `json:"credential,omitempty"`
}

type GetCredentialByIssuerRequest struct {
	Issuer string `json:"issuer" validate:"required"`
}

type GetCredentialBySubjectRequest struct {
	Subject string `json:"subject" validate:"required"`
}

type GetCredentialBySchemaRequest struct {
	Schema string `json:"schema" validate:"required"`
}

type GetCredentialsResponse struct {
	Credentials []credential.Container `json:"credentials,omitempty"`
}

type DeleteCredentialRequest struct {
	ID string `json:"id" validate:"required"`
}
