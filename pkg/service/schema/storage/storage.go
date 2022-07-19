package storage

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential/schema"

	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredSchema struct {
	Schema schema.VCJSONSchema `json:"schema"`
}

type Storage interface {
	StoreSchema(schema StoredSchema) error
	GetSchema(id string) (*StoredSchema, error)
	// TODO(gabe) consider get schemas by DID, or more advanced querying
	GetSchemas() ([]StoredSchema, error)
	DeleteSchema(id string) error
}

// NewSchemaStorage finds the schema storage impl for a given ServiceStorage value
func NewSchemaStorage(s storage.ServiceStorage) (Storage, error) {
	switch s.Type() {
	case storage.Bolt:
		gotBolt, ok := s.(*storage.BoltDB)
		if !ok {
			errMsg := fmt.Sprintf("trouble instantiating : %s", s.Type())
			return nil, util.LoggingNewError(errMsg)
		}
		boltStorage, err := NewBoltSchemaStorage(gotBolt)
		if err != nil {
			return nil, util.LoggingErrorMsg(err, "could not instantiate schema bolt storage")
		}
		return boltStorage, err
	default:
		errMsg := fmt.Errorf("unsupported storage type: %s", s.Type())
		return nil, util.LoggingError(errMsg)
	}
}
