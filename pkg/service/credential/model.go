package credential

import (
	credsdk "github.com/TBD54566975/ssi-sdk/credential"
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

type CreateCredentialResponse struct {
	Credential credsdk.VerifiableCredential
}

type GetCredentialRequest struct {
	ID string
}

type GetCredentialResponse struct {
	Credential credsdk.VerifiableCredential
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
	Credentials []credsdk.VerifiableCredential
}

type DeleteCredentialRequest struct {
	ID string
}
