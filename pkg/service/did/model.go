package did

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/crypto"
	didsdk "github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/tbd54566975/ssi-service/pkg/server/pagination"
)

type GetSupportedMethodsResponse struct {
	Methods []didsdk.Method `json:"method"`
}

type ResolveDIDRequest struct {
	DID string `json:"did" validate:"required"`
}

type ResolveDIDResponse struct {
	ResolutionMetadata  *resolution.Metadata         `json:"didResolutionMetadata,omitempty"`
	DIDDocument         *didsdk.Document             `json:"didDocument"`
	DIDDocumentMetadata *resolution.DocumentMetadata `json:"didDocumentMetadata,omitempty"`
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

type ListDIDsRequest struct {
	Method  didsdk.Method `json:"method" validate:"required"`
	Deleted bool          `json:"deleted"`

	// When nil, all DIDs will be returned.
	PageRequest *pagination.PageRequest
}

// ListDIDsResponse is the JSON-serializable response for getting all DIDs for a given method
type ListDIDsResponse struct {
	DIDs          []didsdk.Document `json:"dids"`
	NextPageToken string
}

type DeleteDIDRequest struct {
	Method didsdk.Method `json:"method" validate:"required"`
	ID     string        `json:"id" validate:"required"`
}
