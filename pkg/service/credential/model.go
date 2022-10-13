package credential

import (
	"github.com/tbd54566975/ssi-service/internal/credential"
)

const (
	SchemaType string = "JsonSchemaValidator2018"
)

type CreateCredentialRequest struct {
	Issuer  string
	Subject string
	// A context is optional. If not present, we'll apply default, required context values.
	Context string
	// A schema is optional. If present, we'll attempt to look it up and validate the data against it.
	JSONSchema string
	Data       map[string]interface{}
	Expiry     string
	// TODO(gabe) support more capabilities like signature type, format, status, and more.
}

// CreateCredentialResponse holds a resulting credential from credential creation, which is an XOR type:
// containing either a Data Integrity Proofed credential or a VC-JWT representation.
type CreateCredentialResponse struct {
	credential.Container
}

type GetCredentialRequest struct {
	ID string
}

type GetCredentialResponse struct {
	credential.Container
}

type GetCredentialByIssuerRequest struct {
	Issuer string
}

type GetCredentialBySubjectRequest struct {
	Subject string
}

type GetCredentialBySchemaRequest struct {
	Schema string
}

type GetCredentialsResponse struct {
	Credentials []credential.Container
}

type DeleteCredentialRequest struct {
	ID string
}
