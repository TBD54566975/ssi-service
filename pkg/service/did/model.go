package did

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	sdkdid "github.com/TBD54566975/ssi-sdk/did"
)

type GetSupportedMethodsResponse struct {
	Methods []Method `json:"methods"`
}

// CreateDIDRequest is the JSON-serializable request for creating a DID across DID methods
type CreateDIDRequest struct {
	Method  Method         `json:"method" validate:"required"`
	KeyType crypto.KeyType `validate:"required"`
}

// CreateDIDResponse is the JSON-serializable response for creating a DID
type CreateDIDResponse struct {
	DID sdkdid.DIDDocument `json:"did"`
	// TODO(gabe) this is temporary, and should never be exposed like this!
	PrivateKey string `json:"base58PrivateKey"`
}

type GetDIDRequest struct {
	Method Method `json:"method" validate:"required"`
	ID     string `json:"id" validate:"required"`
}

// GetDIDResponse is the JSON-serializable response for getting a DID
type GetDIDResponse struct {
	DID sdkdid.DIDDocument `json:"did"`
}
