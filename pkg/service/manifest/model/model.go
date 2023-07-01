package model

import (
	"time"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
	sdkutil "github.com/TBD54566975/ssi-sdk/util"
	"github.com/tbd54566975/ssi-service/pkg/service/common"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/pkg/service/manifest/storage"
)

// Manifest

type CreateManifestRequest struct {
	Name                               *string                        `json:"name,omitempty"`
	Description                        *string                        `json:"description,omitempty"`
	IssuerDID                          string                         `json:"issuerDid" validate:"required"`
	FullyQualifiedVerificationMethodID string                         `json:"fullyQualifiedVerificationMethodId" validate:"required"`
	IssuerName                         *string                        `json:"issuerName,omitempty"`
	OutputDescriptors                  []manifestsdk.OutputDescriptor `json:"outputDescriptors" validate:"required,dive"`
	ClaimFormat                        *exchange.ClaimFormat          `json:"format" validate:"required,dive"`
	PresentationDefinitionRef          *PresentationDefinitionRef     `json:"presentationDefinitionRef,omitempty" validate:"omitempty,dive"`
}

func (r CreateManifestRequest) IsValid() error {
	if err := sdkutil.IsValidStruct(r); err != nil {
		return err
	}
	return common.ValidateVerificationMethodID(r.FullyQualifiedVerificationMethodID, r.IssuerDID)
}

type CreateManifestResponse struct {
	Manifest manifestsdk.CredentialManifest `json:"manifest"`
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
	Manifest manifestsdk.CredentialManifest `json:"manifest"`
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

type CreateRequestRequest struct {
	ManifestRequest Request `json:"manifestRequest"`
}

type CreateRequestResponse struct {
	ManifestRequest Request `json:"manifestRequest"`
}

type GetRequestRequest struct {
	ID string `json:"id" validate:"required"`
}

type GetRequestResponse struct {
	ID              string  `json:"id"`
	ManifestRequest Request `json:"manifestRequest"`
}

type DeleteRequestRequest struct {
	ID string `json:"id" validate:"required"`
}

type ListRequestsResponse struct {
	ManifestRequests []Request `json:"manifestRequests"`
}

type Request struct {
	common.Request

	// ID of the credential manifest used for this request.
	ManifestID string `json:"manifestId" validate:"required"`

	// CredentialManifestJWT is a JWT token with a "presentation_definition" claim within it. The
	// value of the field named "presentation_definition.id" matches PresentationDefinitionID.
	// This is an output only field.
	CredentialManifestJWT keyaccess.JWT `json:"credentialManifestJwt"`
}

type PresentationDefinitionRef struct {
	// id of the presentation definition created with PresentationDefinitionAPI. Must be empty if `value` is present.
	ID *string `json:"presentationDefinitionId"`

	// value of the presentation definition to use. Must be empty if `id` is present.
	PresentationDefinition *exchange.PresentationDefinition `json:"presentationDefinition" validate:"omitempty,dive"`
}
