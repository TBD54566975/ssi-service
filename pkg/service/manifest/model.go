package manifest

import (
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"

	cred "github.com/tbd54566975/ssi-service/internal/credential"
)

// Manifest

type CreateManifestRequest struct {
	Manifest manifestsdk.CredentialManifest
}

type CreateManifestResponse struct {
	Manifest manifestsdk.CredentialManifest
}

type GetManifestRequest struct {
	ID string
}

type GetManifestResponse struct {
	Manifest manifestsdk.CredentialManifest
}

type GetManifestsResponse struct {
	Manifests []manifestsdk.CredentialManifest
}

type DeleteManifestRequest struct {
	ID string
}

// Application

type SubmitApplicationRequest struct {
	Application  manifestsdk.CredentialApplication
	RequesterDID string
}

type SubmitApplicationResponse struct {
	Response   manifestsdk.CredentialResponse
	Credential []cred.CredentialContainer
}

type GetApplicationRequest struct {
	ID string
}

type GetApplicationResponse struct {
	Application manifestsdk.CredentialApplication
}

type GetApplicationsResponse struct {
	Applications []manifestsdk.CredentialApplication
}

type DeleteApplicationRequest struct {
	ID string
}

// Response

type GetResponseRequest struct {
	ID string
}

type GetResponseResponse struct {
	Response manifestsdk.CredentialResponse
}

type GetResponsesResponse struct {
	Responses []manifestsdk.CredentialResponse
}

type DeleteResponseRequest struct {
	ID string
}
