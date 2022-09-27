package dwn

import manifestsdk "github.com/TBD54566975/ssi-sdk/credential/manifest"

type DWNPublishManifestRequest struct {
	ManifestID string
}

type DWNPublishManifestResponse struct {
	Manifest manifestsdk.CredentialManifest
}
