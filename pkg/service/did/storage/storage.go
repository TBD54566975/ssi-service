package storage

import (
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredDID struct {
	DID              did.DIDDocument `json:"did"`
	PrivateKeyBase58 string          `json:"privateKeyBase58"`
}

type Storage interface {
	StoreDID(did StoredDID) error
	GetDID(id string) (*StoredDID, error)
	GetDIDs(method string) ([]StoredDID, error)
	DeleteDID(id string) error
}

// NewDIDStorage finds the Author storage impl for a given ServiceStorage value
func NewDIDStorage(s storage.ServiceStorage) (Storage, error) {
	gotBolt, ok := s.(*storage.BoltDB)
	if !ok {
		return nil, errors.New("unsupported storage type")
	}
	boltStorage, err := NewBoltDIDStorage(gotBolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate Author Bolt storage")
	}
	return boltStorage, err
}
