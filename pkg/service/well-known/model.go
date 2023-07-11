package wellknown

import (
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/internal/credential"
)

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

func (c *DIDConfiguration) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	c.Context = m["@context"]

	linkedDIDs, ok := m["linked_dids"].([]any)
	if !ok {
		return errors.New("linked_dids expected to be array")
	}
	var err error
	c.LinkedDIDs, err = credential.NewCredentialContainerFromArray(linkedDIDs)
	if err != nil {
		return err
	}
	return nil
}

type VerifyDIDConfigurationRequest struct {
	// Represents an origin to fetch the DID Configuration Resource from. Must be serialized as described in https://html.spec.whatwg.org/multipage/browsers.html#origin.
	// The `scheme` MUST be `https`.
	Origin string `json:"origin" validate:"required" example:"https://example.com"`
}

type VerifyDIDConfigurationResponse struct {
	// Whether the DIDConfiguration was verified.
	Verified bool `json:"verified"`

	// The configuration that was fetched from the origin's well known location.
	DIDConfiguration string `json:"didConfiguration"`

	// When Verified == false, the reason why it wasn't verified.
	Reason string `json:"reason,omitempty"`
}
