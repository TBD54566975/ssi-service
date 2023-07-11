package wellknown

import "github.com/tbd54566975/ssi-service/internal/credential"

type CreateDIDConfigurationRequest struct {
	IssuerDID            string
	VerificationMethodID string
	Origin               string

	ExpirationDate string

	// When empty, now will be used.
	IssuanceDate string
}

type CreateDIDConfigurationResponse struct {
	// The DID Configuration Resource value to host.
	DIDConfiguration DIDConfiguration `json:"didConfiguration"`

	// URL where the `didConfiguration` value should be hosted at.
	WellKnownLocation string `json:"wellKnownLocation"`
}

const (
	DIDConfigurationContext        = "https://identity.foundation/.well-known/did-configuration/v1"
	DIDConfigurationLocationSuffix = "/.well-known/did-configuration.json"
)

type DIDConfiguration struct {
	Context    any                    `json:"@context" validate:"required"`
	LinkedDIDs []credential.Container `json:"linked_dids" validate:"required"`
}
