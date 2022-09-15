package manifest

import (
	"github.com/TBD54566975/ssi-sdk/credential"
	exchangesdk "github.com/TBD54566975/ssi-sdk/credential/exchange"
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
)

// Manifest
type CreateManifestRequest struct {
	Issuer string
	// A context is optional. If not present, we'll apply default, required context values.
	Context                string
	OutputDescriptors      []manifestsdk.OutputDescriptor
	PresentationDefinition exchangesdk.PresentationDefinition
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
	ManifestID             string
	PresentationSubmission exchangesdk.PresentationSubmission
}

type SubmitApplicationResponse struct {
	Response   manifestsdk.CredentialResponse
	Credential credential.VerifiableCredential
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
