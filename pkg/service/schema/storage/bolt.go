package storage

import (
	"fmt"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
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
		err := errors.New("could not store schema without an ID")
		logrus.WithError(err).Error()
		return err
	}
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		errMsg := fmt.Sprintf("could not store schema: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return b.db.Write(namespace, id, schemaBytes)
}

func (b BoltSchemaStorage) GetSchema(id string) (*StoredSchema, error) {
	schemaBytes, err := b.db.Read(namespace, id)
	if err != nil {
		errMsg := fmt.Sprintf("could not get schema: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	if len(schemaBytes) == 0 {
		err := fmt.Errorf("schema not found with id: %s", id)
		logrus.WithError(err).Error("could not get schema from storage")
		return nil, err
	}
	var stored StoredSchema
	if err := json.Unmarshal(schemaBytes, &stored); err != nil {
		errMsg := fmt.Sprintf("could not unmarshal stored schema: %s", id)
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrapf(err, errMsg)
	}
	return &stored, nil
}

// GetSchemas attempts to get all stored schemas. It will return those it can even if it has trouble with some.
func (b BoltSchemaStorage) GetSchemas() ([]StoredSchema, error) {
	gotSchemas, err := b.db.ReadAll(namespace)
	if err != nil {
		errMsg := "could not get all schemas"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	if len(gotSchemas) == 0 {
		logrus.Info("no schemas to get")
		return nil, nil
	}
	var stored []StoredSchema
	for _, schemaBytes := range gotSchemas {
		var nextSchema StoredSchema
		if err := json.Unmarshal(schemaBytes, &nextSchema); err == nil {
			stored = append(stored, nextSchema)
		}
	}
	return stored, nil
}

func (b BoltSchemaStorage) DeleteSchema(id string) error {
	if err := b.db.Delete(namespace, id); err != nil {
		errMsg := fmt.Sprintf("could not delete schema: %s", id)
		logrus.WithError(err).Error(errMsg)
		return errors.Wrapf(err, errMsg)
	}
	return nil
}
