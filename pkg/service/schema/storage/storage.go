package storage

import (
	"github.com/TBD54566975/ssi-sdk/credential/schema"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
	"github.com/tbd54566975/ssi-service/internal/util"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

type StoredSchema struct {
	ID        string              `json:"id"`
	Schema    schema.VCJSONSchema `json:"schema"`
	SchemaJWT *keyaccess.JWT      `json:"token,omitempty"`
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
	boltStorage, err := NewBoltSchemaStorage(s)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not instantiate schema bolt storage")
	}
	return boltStorage, err
}
