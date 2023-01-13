package issuing

import (
	"time"

	"github.com/TBD54566975/ssi-sdk/util"
	"go.einride.tech/aip/filtering"
)

type GetIssuanceTemplateRequest struct {
	ID string `json:"id" validate:"required"`
}

type TimeLike struct {
	// For fixed time in the future.
	Time *time.Time `json:"time,omitempty"`

	// For a fixed offset from when it was issued.
	Duration *time.Duration `json:"duration,omitempty"`
}

type ClaimTemplates map[string]any

type CredentialTemplate struct {
	// ID corresponding to an OutputDescriptor.ID from the manifest.
	ID string `json:"id"`

	// ID of the CredentialSchema to be used for the issued credential.
	Schema string `json:"schema"`

	// Optional.
	// When present, it's the ID of the input descriptor in the application. Corresponds to one of the
	// PresentationDefinition.InputDescriptors[].ID in the credential manifest. When creating a credential, the base
	// data will be populated from the provided submission that matches this ID.
	// When absent, there will be no base data for the credentials created. Additionally, no JSON path strings in
	// ClaimTemplates.Data will be resolved.
	CredentialInputDescriptor string `json:"credentialInputDescriptor"`

	// Data that will be used to determine credential claims.
	// Values may be json path like strings, or any other JSON primitive. Each entry will be used to come up with a
	// claim about the credentialSubject in the credential that will be issued.
	Data ClaimTemplates `json:"data,omitempty"`

	// Parameter to determine the expiry of the credential.
	Expiry TimeLike `json:"expiry,omitempty"`

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
