package model

// CredentialResponse represents a response from a Credential Issuer to a Credential Request.
type CredentialResponse struct {
	// format: REQUIRED. JSON string denoting the format of the issued Credential.
	Format string `json:"format"`

	// credential: OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned.
	// MAY be a JSON string or a JSON object, depending on the Credential format. See Appendix E for the Credential format specific encoding requirements.
	Credential string `json:"credential,omitempty"`

	// acceptance_token: OPTIONAL. A JSON string containing a security token subsequently used to obtain a Credential.
	// MUST be present when credential is not returned.
	AcceptanceToken string `json:"acceptance_token,omitempty"`

	// c_nonce: OPTIONAL. JSON string containing a nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2).
	// When received, the Wallet MUST use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce.
	CNonce string `json:"c_nonce,omitempty"`

	// c_nonce_expires_in: OPTIONAL. JSON integer denoting the lifetime in seconds of the c_nonce.
	// Note that this is an integer, not a string, as specified in the text.
	CNonceExpiresIn int `json:"c_nonce_expires_in,omitempty"`
}
