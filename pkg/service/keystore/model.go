package keystore

import (
	gocrypto "crypto"

	"github.com/TBD54566975/ssi-sdk/crypto"
)

type StoreKeyRequest struct {
	ID               string
	Type             crypto.KeyType
	Controller       string
	PrivateKeyBase58 string
}

type GetKeyRequest struct {
	ID string
}

type GetKeyResponse struct {
	ID         string
	Type       crypto.KeyType
	Controller string
	CreatedAt  string
	Key        gocrypto.PrivateKey
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

type DeleteKeyRequest struct {
	ID string
}

type DeleteKeyResponse struct {
}
