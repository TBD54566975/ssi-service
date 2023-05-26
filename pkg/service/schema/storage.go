package schema

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/credential/schema"

	"github.com/tbd54566975/ssi-service/pkg/storage"

	"github.com/tbd54566975/ssi-service/internal/keyaccess"
)

const (
	namespace = "schema"
)

type StoredSchema struct {
	ID               string            `json:"id"`
	Schema           schema.JSONSchema `json:"schema"`
	CredentialSchema *keyaccess.JWT    `json:"credentialSchema,omitempty"`
}

type Storage struct {
	db storage.ServiceStorage
}

func NewSchemaStorage(db storage.ServiceStorage) (*Storage, error) {
	if db == nil {
		return nil, errors.New("db reference is nil")
	}
	return &Storage{db: db}, nil
}

func (ss *Storage) StoreSchema(ctx context.Context, schema StoredSchema) error {
	id := schema.ID
	if id == "" {
		return util.LoggingNewError("could not store schema without an ID")
	}
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return util.LoggingErrorMsgf(err, "could not store schema: %s", id)
	}
	return ss.db.Write(ctx, namespace, id, schemaBytes)
}

func (ss *Storage) GetSchema(ctx context.Context, id string) (*StoredSchema, error) {
	schemaBytes, err := ss.db.Read(ctx, namespace, id)
	if err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not get schema: %s", id)
	}
	if len(schemaBytes) == 0 {
		return nil, util.LoggingNewErrorf("schema not found with id: %s", id)
	}
	var stored StoredSchema
	if err = json.Unmarshal(schemaBytes, &stored); err != nil {
		return nil, util.LoggingErrorMsgf(err, "could not unmarshal stored schema: %s", id)
	}
	return &stored, nil
}

// ListSchemas attempts to get all stored schemas. It will return those it can even if it has trouble with some.
func (ss *Storage) ListSchemas(ctx context.Context) ([]StoredSchema, error) {
	gotSchemas, err := ss.db.ReadAll(ctx, namespace)
	if err != nil {
		return nil, util.LoggingErrorMsg(err, "could not list schemas")
	}
	if len(gotSchemas) == 0 {
		logrus.Info("no schemas to list")
		return nil, nil
	}
	var stored []StoredSchema
	for _, schemaBytes := range gotSchemas {
		var nextSchema StoredSchema
		if err = json.Unmarshal(schemaBytes, &nextSchema); err == nil {
			stored = append(stored, nextSchema)
		} else {
			logrus.WithError(err).Errorf("could not unmarshal stored schema: %s", string(schemaBytes))
		}
	}
	return stored, nil
}

func (ss *Storage) DeleteSchema(ctx context.Context, id string) error {
	if err := ss.db.Delete(ctx, namespace, id); err != nil {
		return util.LoggingErrorMsgf(err, "could not delete schema: %s", id)
	}
	return nil
}
