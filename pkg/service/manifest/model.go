package manifest

import (
	exchangesdk "github.com/TBD54566975/ssi-sdk/credential/exchange"
	applicationsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
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
type CreateApplicationRequest struct {
	ManifestID             string
	PresentationSubmission exchangesdk.PresentationSubmission
}

type CreateApplicationResponse struct {
	Application applicationsdk.CredentialApplication
}

type GetApplicationRequest struct {
	ID string
}

type GetApplicationResponse struct {
	Application applicationsdk.CredentialApplication
}

type GetApplicationsResponse struct {
	Applications []applicationsdk.CredentialApplication
}

type DeleteApplicationRequest struct {
	ID string
}
