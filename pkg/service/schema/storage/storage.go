package storage

import (
	"github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
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
	gotBolt, ok := s.(*storage.BoltDB)
	if !ok {
		return nil, errors.New("unsupported storage type")
	}
	boltStorage, err := NewBoltSchemaStorage(gotBolt)
	if err != nil {
		return nil, errors.Wrap(err, "could not instantiate schema bolt storage")
	}
	return boltStorage, err
}
