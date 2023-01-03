package issuing

import (
	"time"

	"github.com/TBD54566975/ssi-sdk/util"
	"go.einride.tech/aip/filtering"
)

type GetIssuanceTemplateRequest struct {
	ID string `json:"id" validate:"required"`
}

type CredentialTemplateData struct {
	// Optional. When present, it's the ID of the input descriptor in the application. Corresponds to one of the
	// PresentationDefinition.InputDescriptors[].ID in the credential manifest.
	CredentialInputDescriptor string `json:"credentialInputDescriptor"`

	// The set of information that will be used to create claims.
	Claims ClaimTemplates
}

type TimeLike struct {
	// For fixed time in the future.
	Time *time.Time

	// For a fixed offset from when it was issued.
	Duration *time.Duration
}

type ClaimTemplates struct {
	// Values may be json path like strings, or any other JSON primitive. Each entry will be used to come up with a
	// claim about the credentialSubject in the credential that will be issued.
	Data map[string]any
}

type CredentialTemplate struct {
	// ID corresponding to an OutputDescriptor.ID from the manifest.
	ID string `json:"id"`

	// ID of the CredentialSchema to be used for the issued credential.
	Schema string `json:"schema"`

	// Date that will be used to determine credential claims.
	Data CredentialTemplateData `json:"data"`

	// Parameter to determine the expiry of the credential.
	Expiry TimeLike `json:"expiry"`

	// Whether the credentials created should be revocable.
	Revocable bool `json:"revocable"`
}

type IssuanceTemplate struct {
	// ID of this template.
	ID string `json:"id"`

	// ID of the credential manifest that this template corresponds to.
	CredentialManifest string `json:"credentialManifest" validate:"required"`

	// ID of the issuer that will be issuing the credentials.
	Issuer string `json:"issuer" validate:"required"`

	// Info required to create a credential from a credential application.
	Credentials []CredentialTemplate `json:"credentials"`
}

type GetIssuanceTemplateResponse struct {
	// The template that was requested.
	IssuanceTemplate *IssuanceTemplate `json:"issuanceTemplate"`
}

type CreateIssuanceTemplateRequest struct {
	// The template to create.
	IssuanceTemplate IssuanceTemplate `json:"issuanceTemplate"`
}

func (r CreateIssuanceTemplateRequest) IsValid() bool {
	return util.IsValidStruct(r) == nil
}

type DeleteIssuanceTemplateRequest struct {
	// ID of the template that will be deleted.
	// Required.
	ID string `json:"id" validate:"required"`
}

type ListIssuanceTemplatesRequest struct {
	// A parsed filter expression conforming to https://google.aip.dev/160.
	Filter filtering.Filter
}

func (r ListIssuanceTemplatesRequest) Validate() error {
	return util.NewValidator().Struct(r)
}

type ListIssuanceTemplatesResponse struct {
	// The issuance templates that satisfy the query conditions.
	IssuanceTemplates []IssuanceTemplate `json:"issuanceTemplates"`
}
