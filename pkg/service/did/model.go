package did

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
)

type GetSupportedMethodsResponse struct {
	Methods []didsdk.Method `json:"method"`
}

type ResolveDIDRequest struct {
	DID string `json:"did" validate:"required"`
}

type ResolveDIDResponse struct {
	ResolutionMetadata  *didsdk.ResolutionMetadata `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.Document           `json:"didDocument"`
	DIDDocumentMetadata *didsdk.DocumentMetadata   `json:"didDocumentMetadata,omitempty"`
}

type CreateDIDRequestOptions interface {
	Method() didsdk.Method
}

// CreateDIDRequest is the JSON-serializable request for creating a DID across DID method
type CreateDIDRequest struct {
	Method  didsdk.Method           `json:"method" validate:"required"`
	KeyType crypto.KeyType          `validate:"required"`
	Options CreateDIDRequestOptions `json:"options"`
}

// CreateDIDResponse is the JSON-serializable response for creating a DID
type CreateDIDResponse struct {
	DID didsdk.Document `json:"did"`
	// TODO(gabe): change to returning a set of public keys. private keys should be stored in the keystore,
	//  and stay within the service boundary. This will unify the solution for both custodial and non-custodial keys.
	// https://github.com/TBD54566975/ssi-service/issues/371
	PrivateKeyBase58 string         `json:"base58PrivateKey"`
	KeyType          crypto.KeyType `json:"keyType"`
}

type GetDIDRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
	ID     string        `json:"id" validate:"required"`
}

// GetDIDResponse is the JSON-serializable response for getting a DID
type GetDIDResponse struct {
	DID didsdk.Document `json:"did"`
}

type GetKeyFromDIDRequest struct {
	ID    string `json:"id" validate:"required"`
	KeyID string `json:"keyId,omitempty"`
}

type GetKeyFromDIDResponse struct {
	KeyID     string             `json:"keyId"`
	PublicKey gocrypto.PublicKey `json:"publicKey"`
}

type GetDIDsRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
}

// GetDIDsResponse is the JSON-serializable response for getting all DIDs for a given method
type GetDIDsResponse struct {
	DIDs []didsdk.Document `json:"dids"`
}

type DeleteDIDRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
	ID     string        `json:"id" validate:"required"`
}
