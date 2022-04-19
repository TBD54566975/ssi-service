package storage

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/tbd54566975/ssi-service/pkg/storage"
)

const (
	namespace = "schema"
)

type BoltSchemaStorage struct {
	db *storage.BoltDB
}

func NewBoltSchemaStorage(db *storage.BoltDB) (*BoltSchemaStorage, error) {
	if db == nil {
		return nil, errors.New("bolt db reference is nil")
	}
	return &BoltSchemaStorage{db: db}, nil
}

func (b BoltSchemaStorage) StoreSchema(schema StoredSchema) error {
	id := schema.Schema.ID
	if id == "" {
		return errors.New("could not store schema without an ID")
	}
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return errors.Wrapf(err, "could not store Schema: %s", id)
	}
	return b.db.Write(namespace, id, schemaBytes)
}

func (b BoltSchemaStorage) GetSchema(id string) (*StoredSchema, error) {
	schemaBytes, err := b.db.Read(namespace, id)
	if err != nil {
		return nil, errors.Wrapf(err, "could not get schema: %s", id)
	}
	if len(schemaBytes) == 0 {
		return nil, fmt.Errorf("schema not found with id: %s", id)
	}
	var stored StoredSchema
	if err := json.Unmarshal(schemaBytes, &stored); err != nil {
		return nil, errors.Wrapf(err, "could not unmarshal stored schema: %s", id)
	}
	return &stored, nil
}

// GetSchemas attempts to get all stored schemas. It will return those it can even if it has trouble with some.
func (b BoltSchemaStorage) GetSchemas() ([]StoredSchema, error) {
	gotSchemas, err := b.db.ReadAll(namespace)
	if err != nil {
		return nil, errors.Wrap(err, "could not get all schemas")
	}
	if len(gotSchemas) == 0 {
		return nil, nil
	}
	var stored []StoredSchema
	for _, schemaBytes := range gotSchemas {
		var nextSchema StoredSchema
		if err := json.Unmarshal(schemaBytes, &nextSchema); err != nil {
			stored = append(stored, nextSchema)
		}
	}
	return stored, nil
}

func (b BoltSchemaStorage) DeleteSchema(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
		return errors.Wrapf(err, "could not delete schema: %s", id)
	}
	return nil
}
