package storage

import (
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredOperation struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	Error string `json:"errorResult"`
}

type Storage interface {
	StoreOperation(op StoredOperation) error
	GetOperation(id string) (*StoredOperation, error)
	GetOperations() ([]StoredOperation, error)
	DeleteOperation(id string) error
}

func NewOperationStorage(s storage.ServiceStorage) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			return nil, util.LoggingNewErrorf("trouble instantiating : %s", s.Type())
		}
		boltStorage, err := NewBoltOperationStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate schema bolt storage")
		}
		return boltStorage, err
	default:
		return nil, util.LoggingNewErrorf("unsupported storage type: %s", s.Type())
	}
}
