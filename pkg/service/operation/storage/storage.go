package storage

import (
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
	"go.einride.tech/aip/filtering"
)

type StoredOperation struct {
	ID string `json:"id"`

	// Whether this operation has finished.
	Done bool `json:"done"`

	// Populated when there was an error with the operation.
	Error string `json:"errorResult,omitempty"`

	// Populated only when Done == true and Error == ""
	Response []byte `json:"response,omitempty"`
}

func (s StoredOperation) FilterVariablesMap() map[string]any {
	return map[string]any{
		"done": s.Done,
		// "true" and "false" are currently being parsed as identifiers, so we need to pass in the values that they
		// evaluate to. Ideally, we should change them to be parsed as constants. That requires an upstream change in
		// the filtering library.
		"true":  true,
		"false": false,
	}
}

type Storage interface {
	StoreOperation(op StoredOperation) error
	GetOperation(id string) (StoredOperation, error)
	GetOperations(parent string, filter filtering.Filter) ([]StoredOperation, error)
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
