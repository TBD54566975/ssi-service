package router

type CommonCreateRequestRequest struct {
	// Audience as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	// Optional
	Audience []string `json:"audience"`

	// Expiration as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
	// Optional.
	Expiration string `json:"expiration"`

	// DID of the issuer of this presentation definition. The DID must have been previously created with the DID API,
	// or the PrivateKey must have been added independently.
	IssuerDID string `json:"issuerId" validate:"required"`

	// The privateKey associated with the KID will be used to sign an envelope that contains
	// the created presentation definition.
	IssuerKID string `json:"issuerKid" validate:"required"`
}
