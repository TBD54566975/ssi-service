package keystore

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

type StoreKeyRequest struct {
	ID         string
	Type       crypto.KeyType
	Controller string
	Key        []byte
}

type GetKeyRequest struct {
	ID string
}

type GetKeyResponse struct {
	ID         string
	Type       crypto.KeyType
	Controller string
	CreatedAt  string
	Key        []byte
}

type GetKeyDetailsRequest struct {
	ID string
}

type GetKeyDetailsResponse struct {
	ID         string
	Type       crypto.KeyType
	Controller string
	CreatedAt  string
}
