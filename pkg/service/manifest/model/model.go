package model

import (
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
)

// Manifest

type CreateManifestRequest struct {
	Name                   *string                          `json:"name,omitempty"`
	Description            *string                          `json:"description,omitempty"`
	IssuerDID              string                           `json:"issuerDid" validate:"required"`
	IssuerKID              string                           `json:"issuerKid" validate:"required"`
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

type ListManifestsResponse struct {
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
	ApplicationJSON map[string]any                    `json:"applicationJson,omitempty"`
}

type SubmitApplicationResponse struct {
	Response    manifestsdk.CredentialResponse `json:"response" validate:"required"`
	Credentials []any                          `json:"credentials,omitempty"`
	ResponseJWT keyaccess.JWT                  `json:"responseJwt,omitempty" validate:"required"`
}

type GetApplicationRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetApplicationResponse struct {
	// One of "pending", "fulfilled", "rejected". When Status is either fulfilled or rejected, a corresponding
	// SubmissionApplicationResponse is guaranteed to exist.
	Status      string
	Application manifestsdk.CredentialApplication `json:"application"`
}

type ListApplicationsResponse struct {
	Applications []manifestsdk.CredentialApplication `json:"applications,omitempty"`
}

type DeleteApplicationRequest struct {
	ID string `json:"id,omitempty" validate:"required"`
}

// ReviewApplicationRequest is something foobar
type ReviewApplicationRequest struct {
	// ID of the application.
	ID       string `json:"id" validate:"required"`
	Approved bool   `json:"approved" validate:"required"`
	// Reason is only used upon denial
	Reason string `json:"reason"`
	// TODO(gabe) add a way to specify which input descriptors resulted in the failure

	CredentialOverrides map[string]CredentialOverride `json:"credentialOverrides,omitempty"`
}

// Response

type GetResponseRequest struct {
	ID string `json:"id,omitempty" validate:"required"`
}

type GetResponseResponse struct {
	Response    manifestsdk.CredentialResponse `json:"response"`
	Credentials any
	ResponseJWT keyaccess.JWT
}

type ListResponsesResponse struct {
	Responses []manifestsdk.CredentialResponse `json:"responses,omitempty"`
}

type DeleteResponseRequest struct {
	ID string `json:"id" validate:"required"`
}

// ServiceModel creates a SubmitApplicationResponse from a given StoredResponse.
func ServiceModel(storedResponse *storage.StoredResponse) SubmitApplicationResponse {
	return SubmitApplicationResponse{
		Response:    storedResponse.Response,
		Credentials: cred.ContainersToInterface(storedResponse.Credentials),
		ResponseJWT: storedResponse.ResponseJWT,
	}
}

type CredentialOverride struct {
	// Data that will be used to determine credential claims.
	Data map[string]any `json:"data"`

	// Parameter to determine the expiry of the credential.
	Expiry *time.Time `json:"expiry"`

	// Whether the credentials created should be revocable.
	Revocable bool `json:"revocable"`
}
