package storage

import (
	"github.com/TBD54566975/ssi-sdk/did"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredDID struct {
	ID  string          `json:"id"`
	DID did.DIDDocument `json:"did"`
}

type Storage interface {
	StoreDID(did StoredDID) error
	GetDID(id string) (*StoredDID, error)
	GetDIDs(method string) ([]StoredDID, error)
	DeleteDID(id string) error
}

// NewDIDStorage finds the DID storage impl for a given ServiceStorage value
func NewDIDStorage(s storage.ServiceStorage) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			return nil, util.LoggingNewErrorf("trouble instantiating : %s", s.Type())
		}
		boltStorage, err := NewBoltDIDStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate credential bolt storage")
		}
		return boltStorage, err
	default:
		return nil, util.LoggingNewErrorf("unsupported storage type: %s", s.Type())
	}
}
