package model

import "github.com/TBD54566975/ssi-sdk/oidc/issuance"

// CredentialRequest represents a request for a credential.
type CredentialRequest struct {
	// Format is the required format of the credential to be issued.
	Format issuance.Format `json:"format"`

	// Proof is an optional proof of possession of the key material.
	Proof *ProofParameter `json:"proof"`

	// Present when format==jwt_vc_json
	*JWTVCCredentialRequest
}

// JWTProof objects contain a single jwt element with a JWS [RFC7515] as proof of possession. The JWT MUST contain the following elements:
//
// in the JOSE Header,
//
// - typ: REQUIRED. MUST be openid4vci-proof+jwt, which explicitly types the proof JWT as recommended in Section 3.11 of [RFC8725].
// - alg: REQUIRED. A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry. MUST NOT be none or an identifier for a symmetric algorithm (MAC).
// - kid: CONDITIONAL. JOSE Header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to. MUST NOT be present if jwk or x5c is present.
// - jwk: CONDITIONAL. JOSE Header containing the key material the new Credential shall be bound to. MUST NOT be present if kid or x5c is present.
// - x5c: CONDITIONAL. JOSE Header containing a certificate or certificate chain corresponding to the key used to sign the JWT. This element MAY be used to convey a key attestation. In such a case, the actual key certificate will contain attributes related to the key properties. MUST NOT be present if kid or jwk is present.
//
// in the JWT body,
//
// - iss: OPTIONAL (string). The value of this claim MUST be the client_id of the client making the credential request. This claim MUST be omitted if the Access Token authorizing the issuance call was obtained from a Pre-Authorized Code Flow through anonymous access to the Token Endpoint.
// - aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer URL of the Credential Issuer.
// - iat: REQUIRED (number). The value of this claim MUST be the time at which the proof was issued using the syntax defined in [RFC7519].
// - nonce: REQUIRED (string). The value type of this claim MUST be a string, where the value is a c_nonce provided by the Credential Issuer.
type JWTProof struct {
	JWT string `json:"jwt"`
}

// ProofParameter represents a proof object.
type ProofParameter struct {
	// ProofType is the required concrete proof type. Currently, the only possible value is "jwt".
	ProofType string `json:"proof_type"`

	// Present when proof_type == "jwt".
	*JWTProof
}

type JWTVCCredentialRequest struct {
	// Types is a list of credential types. The credential issued by the issuer MUST at least contain the
	// values listed in this claim. At least `VerifiableCredential` must be specified.
	Types []string `json:"types"`

	// This object determines the optional claims to be added to the credential to be issued.
	CredentialSubject map[string]any `json:"credentialSubject,omitempty"`
}
