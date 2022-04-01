package did

import "github.com/TBD54566975/did-sdk/did"

type StoredDID struct {
	DID              did.DIDDocument
	PrivateKeyBase58 string
}

type Storage interface {
	StoreDID(did StoredDID) error
	GetDID(id string) (*StoredDID, error)
	GetDIDs(method string) ([]StoredDID, error)
	DeleteDID(id string) error
}
