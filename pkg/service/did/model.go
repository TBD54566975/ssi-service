package did

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
)

type GetSupportedMethodsResponse struct {
	Methods []didsdk.Method `json:"methods"`
}

type ResolveDIDRequest struct {
	DID string `json:"did" validate:"required"`
}

type ResolveDIDResponse struct {
	ResolutionMetadata  *didsdk.DIDResolutionMetadata `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.DIDDocument           `json:"didDocument"`
	DIDDocumentMetadata *didsdk.DIDDocumentMetadata   `json:"didDocumentMetadata,omitempty"`
}

// CreateDIDRequest is the JSON-serializable request for creating a DID across DID methods
type CreateDIDRequest struct {
	Method  didsdk.Method  `json:"method" validate:"required"`
	KeyType crypto.KeyType `validate:"required"`
}

// CreateDIDResponse is the JSON-serializable response for creating a DID
type CreateDIDResponse struct {
	DID didsdk.DIDDocument `json:"did"`
	// TODO(gabe) this is temporary, and should never be exposed like this!
	PrivateKey string `json:"base58PrivateKey"`
}

type GetDIDRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
	ID     string        `json:"id" validate:"required"`
}

// GetDIDResponse is the JSON-serializable response for getting a DID
type GetDIDResponse struct {
	DID didsdk.DIDDocument `json:"did"`
}

type GetDIDsRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
}

// GetDIDsResponse is the JSON-serializable response for getting all DIDs for a given method
type GetDIDsResponse struct {
	DIDs []didsdk.DIDDocument `json:"dids"`
}
