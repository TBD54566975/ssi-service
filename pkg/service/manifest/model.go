package manifest

import (
	manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"
)

const (
	SchemaType string = "JsonSchemaValidator2018"
)

type CreateManifestRequest struct {
	Issuer string
	// A context is optional. If not present, we'll apply default, required context values.
	Context           string
	OutputDescriptors map[string]interface{}
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

type GetManifestByIssuerRequest struct {
	Issuer string
}

type GetManifestsResponse struct {
	Manifests []manifestsdk.CredentialManifest
}

type DeleteManifestRequest struct {
	ID string
}
