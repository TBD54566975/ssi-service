package did

import (
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

// CreateDIDRequest is the JSON-serializable request for creating a DID across DID method
type CreateDIDRequest struct {
	Method   didsdk.Method  `json:"method" validate:"required"`
	KeyType  crypto.KeyType `validate:"required"`
	DIDWebID string         `json:"didWebId"`
}

// CreateDIDResponse is the JSON-serializable response for creating a DID
type CreateDIDResponse struct {
	DID              didsdk.Document `json:"did"`
	PrivateKeyBase58 string          `json:"base58PrivateKey"`
	KeyType          crypto.KeyType  `json:"keyType"`
}

type GetDIDRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
	ID     string        `json:"id" validate:"required"`
}

// GetDIDResponse is the JSON-serializable response for getting a DID
type GetDIDResponse struct {
	DID didsdk.Document `json:"did"`
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
