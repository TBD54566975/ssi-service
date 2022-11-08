package storage

import (
	"fmt"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredPresentation struct {
	ID                     string                          `json:"id"`
	PresentationDefinition exchange.PresentationDefinition `json:"presentation_definition"`
}

type Storage interface {
	StorePresentation(schema StoredPresentation) error
	GetPresentation(id string) (*StoredPresentation, error)
	DeletePresentation(id string) error
}

// NewPresentationStorage finds the presentation storage impl for a given ServiceStorage value
func NewPresentationStorage(s storage.ServiceStorage) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			errMsg := fmt.Sprintf("trouble instantiating : %s", s.Type())
			return nil, util.LoggingNewError(errMsg)
		}
		boltStorage, err := NewBoltPresentationStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate schema bolt storage")
		}
		return boltStorage, err
	default:
		errMsg := fmt.Errorf("unsupported storage type: %s", s.Type())
		return nil, util.LoggingError(errMsg)
	}
}
