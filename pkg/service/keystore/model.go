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
	PrivateKeyJWK    crypto.PrivateKeyJWK
}

type GetKeyRequest struct {
	ID string
}

type GetKeyResponse struct {
	ID         string
	Type       crypto.KeyType
	Controller string
	CreatedAt  string
	Revoked    bool
	RevokedAt  string
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
	Revoked    bool
	RevokedAt  string
}

type RevokeKeyRequest struct {
	ID string
}
