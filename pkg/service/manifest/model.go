package manifest

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

// Manifest

type CreateManifestRequest struct {
	Name                   *string                          `json:"name,omitempty"`
	Description            *string                          `json:"description,omitempty"`
	IssuerDID              string                           `json:"issuerDid" validate:"required"`
	IssuerName             *string                          `json:"issuerName,omitempty"`
	OutputDescriptors      []manifestsdk.OutputDescriptor   `json:"outputDescriptors" validate:"required,dive"`
	ClaimFormat            *exchange.ClaimFormat            `json:"format" validate:"required,dive"`
	PresentationDefinition *exchange.PresentationDefinition `json:"presentationDefinition,omitempty" validate:"omitempty,dive"`
}

type CreateManifestResponse struct {
	Manifest    manifestsdk.CredentialManifest `json:"manifest"`
	ManifestJWT keyaccess.JWT                  `json:"manifestJwt,omitempty"`
}

type VerifyManifestRequest struct {
	// ManifestJWT contains a `CredentialManifestWrapper` with a top level `credential_manifest` claim
	ManifestJWT keyaccess.JWT `json:"manifestJwt"`
}

type VerifyManifestResponse struct {
	Verified bool   `json:"verified"`
	Reason   string `json:"reason,omitempty"`
}

type GetManifestRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetManifestResponse struct {
	Manifest    manifestsdk.CredentialManifest `json:"manifest"`
	ManifestJWT keyaccess.JWT                  `json:"manifestJwt,omitempty"`
}

type GetManifestsResponse struct {
	Manifests []GetManifestResponse `json:"manifests,omitempty"`
}

type DeleteManifestRequest struct {
	ID string `json:"id" validate:"required"`
}

// Application

type SubmitApplicationRequest struct {
	ApplicantDID    string                            `json:"applicantDid" validate:"required"`
	Application     manifestsdk.CredentialApplication `json:"application" validate:"required"`
	Credentials     []cred.Container                  `json:"credentials,omitempty"`
	ApplicationJWT  keyaccess.JWT                     `json:"applicationJwt,omitempty" validate:"required"`
	ApplicationJSON map[string]interface{}            `json:"applicationJson,omitempty"`
}

type SubmitApplicationResponse struct {
	Response    manifestsdk.CredentialResponse `json:"response" validate:"required"`
	Credentials []interface{}                  `json:"credentials,omitempty"`
	ResponseJWT keyaccess.JWT                  `json:"responseJwt,omitempty" validate:"required"`
}

type GetApplicationRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetApplicationResponse struct {
	Application manifestsdk.CredentialApplication `json:"application"`
}

type GetApplicationsResponse struct {
	Applications []manifestsdk.CredentialApplication `json:"applications,omitempty"`
}

type DeleteApplicationRequest struct {
	ID string `json:"id,omitempty" validate:"required"`
}

// Response

type GetResponseRequest struct {
	ID string `json:"id,omitempty" validate:"required"`
}

type GetResponseResponse struct {
	Response manifestsdk.CredentialResponse `json:"response"`
}

type GetResponsesResponse struct {
	Responses []manifestsdk.CredentialResponse `json:"responses,omitempty"`
}

type DeleteResponseRequest struct {
	ID string `json:"id" validate:"required"`
}
