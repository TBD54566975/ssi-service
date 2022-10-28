package dwn

import manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"

type PublishManifestRequest struct {
	ManifestID string `json:"manifestId" validate:"required"`
}

type PublishManifestResponse struct {
	Manifest manifestsdk.CredentialManifest `json:"manifest,omitempty"`
}
