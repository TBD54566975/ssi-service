package manifest

import (
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

// Manifest

type CreateManifestRequest struct {
	Manifest manifestsdk.CredentialManifest `json:"manifest" validate:"required"`
}

type CreateManifestResponse struct {
	Manifest    manifestsdk.CredentialManifest `json:"manifest"`
	ManifestJWT keyaccess.JWT                  `json:"manifestJwt,omitempty"`
}

type VerifyManifestRequest struct {
	ManifestJWT keyaccess.JWT `json:"manifestJwt"`
}

type VerifyManifestResponse struct {
	Verified bool   `json:"verified" json:"verified"`
	Reason   string `json:"reason,omitempty" json:"reason,omitempty"`
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
	ApplicantDID   string                            `json:"applicantDid" validate:"required"`
	Application    manifestsdk.CredentialApplication `json:"application" validate:"required"`
	Credentials    []cred.Container                  `json:"credentials,omitempty"`
	ApplicationJWT keyaccess.JWT                     `json:"applicationJWT,omitempty" validate:"required"`
}

type SubmitApplicationResponse struct {
	Response    manifestsdk.CredentialResponse `json:"response"`
	Credentials []cred.Container               `json:"credentials,omitempty"`
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
