package router

type CommonCreateRequestRequest struct {
	// Audience as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
	// Optional
	Audience []string `json:"audience"`

	// Expiration as defined in https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.4
	// Optional.
	Expiration string `json:"expiration"`

	// DID of the issuer of this presentation definition. The DID must have been previously created with the DID API.
	IssuerDID string `json:"issuerId" validate:"required"`

	// The id of the verificationMethod (see https://www.w3.org/TR/did-core/#verification-methods) who's privateKey is
	// stored in ssi-service. The verificationMethod must be part of the did document associated with `issuerId`.
	// The private key associated with the verificationMethod's publicKey will be used to sign an envelope that contains
	// the created presentation definition.
	VerificationMethodID string `json:"verificationMethodId" validate:"required" example:"did:key:z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3#z6MkkZDjunoN4gyPMx5TSy7Mfzw22D2RZQZUcx46bii53Ex3"`

	// The URL that the presenter should be submitting the presentation submission to.
	// Optional.
	CallbackURL string `json:"callbackUrl" example:"https://example.com"`
}
