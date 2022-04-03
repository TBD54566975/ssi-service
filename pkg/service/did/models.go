package did

import (
	"github.com/TBD54566975/did-sdk/crypto"
	sdkdid "github.com/TBD54566975/did-sdk/did"
)

// CreateDIDRequest is the  SON-serializable request for creating a DID across DID methods
type CreateDIDRequest struct {
	KeyType crypto.KeyType `validate:"required"`
}

// CreateDIDResponse is the JSON-serializable response for creating a DID
type CreateDIDResponse struct {
	DID sdkdid.DIDDocument `json:"did"`
	// TODO(gabe) this is temporary, and should never be exposed like this!
	PrivateKey string `json:"base58PrivateKey"`
}

// GetDIDResponse is the JSON-serializable response for getting a DID
type GetDIDResponse struct {
	DID sdkdid.DIDDocument `json:"did"`
}
